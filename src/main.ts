import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';
import { ValidationPipe, VersioningType } from '@nestjs/common';
import { NestExpressApplication } from '@nestjs/platform-express';
import { AppLogger } from './logger/logger.service';

import { bootstrapLogger } from './logger/bootstrap-logger';
import { useContainer } from 'class-validator';
import helmet from 'helmet';
import * as cookieParser from 'cookie-parser';
import { setupSwagger } from './common/swagger/setup-swagger';

function parseList(value?: string): string[] {
  return (value ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function validateSecurityConfig(config: ConfigService) {
  const appEnv = config.get<string>('APP_ENV') ?? 'development';
  const isProd = appEnv === 'production';

  const baseUrl = config.get<string>('BASE_URL', 'http://localhost:3000');

  const cookieSameSite = config.get<string>('COOKIE_SAMESITE');
  const cookieCrossSite = config.get<boolean>('COOKIE_CROSS_SITE');

  const corsOrigins = parseList(config.get<string>('CORS_ORIGINS'));
  const csrfOrigins = parseList(config.get<string>('CSRF_TRUSTED_ORIGINS'));

  if (corsOrigins.length === 0) {
    throw new Error(
      'SECURITY: CORS_ORIGINS має бути визначено (у dev/test/prod), щоб уникнути "allow all" за замовчуванням',
    );
  }

  if (corsOrigins.includes('*')) {
    throw new Error(
      'SECURITY: wildcard CORS (*) заборонено (і несумісно з credentials=true)',
    );
  }

  if (!isProd) return;

  if (cookieSameSite === 'none') {
    if (!baseUrl.startsWith('https://')) {
      throw new Error(
        'SECURITY: COOKIE_SAMESITE=none вимагає HTTPS BASE_URL у production',
      );
    }

    if (!cookieCrossSite) {
      throw new Error(
        'SECURITY: COOKIE_SAMESITE=none вимагає увімкнення COOKIE_CROSS_SITE=true',
      );
    }

    if (corsOrigins.some((o) => o.startsWith('http://'))) {
      throw new Error(
        'SECURITY: HTTP origins заборонені, коли увімкнено SameSite=None у production',
      );
    }
  }

  if (
    corsOrigins.some((o) => o.includes('localhost')) ||
    csrfOrigins.some((o) => o.includes('localhost'))
  ) {
    throw new Error('SECURITY: localhost origins заборонені у production');
  }
}

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  useContainer(app.select(AppModule), { fallbackOnErrors: true });

  const logger = await app.resolve(AppLogger);
  app.useLogger(logger);

  const configService = app.get(ConfigService);

  const trustProxy = Number(configService.get('TRUST_PROXY_HOPS') ?? 1);
  app.set('trust proxy', trustProxy);

  const baseUrl = configService.get<string>(
    'BASE_URL',
    'http://localhost:3000',
  );
  const apiPrefix = configService.get<string>('API_PREFIX', 'api');
  const apiVersion = configService.get<string>('API_VERSION', '1');
  const appEnv = configService.get<string>('APP_ENV') ?? 'development';
  const isProd = appEnv === 'production';

  // ---- SECURITY CONFIG VALIDATION ----
  validateSecurityConfig(configService);

  // ---- Helmet ----
  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: true,
        directives: {
          defaultSrc: ["'none'"],
          baseUri: ["'none'"],
          frameAncestors: ["'none'"],
          formAction: ["'none'"],
        },
      },

      hsts: isProd
        ? { maxAge: 15552000, includeSubDomains: true, preload: true }
        : false,

      crossOriginResourcePolicy: { policy: 'same-site' },
      referrerPolicy: { policy: 'no-referrer' },
    }),
  );

  const cookieSecret = configService.get<string>('COOKIE_SECRET');
  if (!cookieSecret) throw new Error('COOKIE_SECRET is not set');
  app.use(cookieParser(cookieSecret));

  // ---- CORS ----
  const origins = parseList(configService.get<string>('CORS_ORIGINS'));

  const corsAllowNoOrigin =
    String(configService.get('CORS_ALLOW_NO_ORIGIN') ?? '')
      .toLowerCase()
      .trim() === 'true';

  app.enableCors({
    origin: (origin, cb) => {
      if (!origin) {
        if (isProd && !corsAllowNoOrigin) {
          return cb(new Error('CORS blocked: missing Origin'), false);
        }
        return cb(null, true);
      }

      if (origins.includes(origin)) return cb(null, true);

      return cb(new Error(`CORS blocked for origin: ${origin}`), false);
    },
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Authorization',
      'Content-Type',
      'Accept',
      'X-CSRF-Token',
      'X-CSRF-API-Key',
    ],
    credentials: true,
    maxAge: 600,
  });

  // ---- Validation ----
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true,
      forbidNonWhitelisted: true,
    }),
  );

  app.setGlobalPrefix(apiPrefix);

  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: apiVersion,
  });

  const { shouldEnableSwagger, apiBase } = setupSwagger(app, configService);

  const port = configService.get<number>('PORT', 3000);
  await app.listen(port);

  logger.log('==============================', 'Bootstrap');
  logger.log('✅ APP STARTED', 'Bootstrap');
  logger.log(`🔌 Listening on port: ${port}`, 'Bootstrap');
  logger.log(`🌐 Trust proxy hops: ${trustProxy}`, 'Bootstrap');
  logger.log(`🌍 ENV: ${appEnv}`, 'Bootstrap');
  logger.log(`🚀 Server: ${apiBase ?? 'n/a'}`, 'Bootstrap');
  logger.log(`🧩 Swagger enabled: ${shouldEnableSwagger}`, 'Bootstrap');
  if (shouldEnableSwagger) {
    logger.log(`📚 Swagger: ${baseUrl}/${apiPrefix}/docs`, 'Bootstrap');
  }
  logger.log('==============================', 'Bootstrap');
}

bootstrap().catch((err: unknown) => {
  bootstrapLogger.error(
    `❌ Failed to start application: ${
      err instanceof Error ? err.stack : String(err)
    }`,
  );
  process.exit(1);
});
