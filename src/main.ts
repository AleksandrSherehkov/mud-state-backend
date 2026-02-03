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

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  useContainer(app.select(AppModule), { fallbackOnErrors: true });

  const logger = await app.resolve(AppLogger);
  app.useLogger(logger);

  const configService = app.get(ConfigService);
  // ---- trust proxy ----
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

  // ---- security middleware ----
  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: true,
        directives: {
          defaultSrc: ["'none'"],
          baseUri: ["'none'"],
          frameAncestors: ["'none'"],
          formAction: ["'none'"],
          // Если вдруг будет HTML/Swagger-UI, эти директивы можно расширять точечно.
          // scriptSrc: ["'self'"],
          // styleSrc: ["'self'", "'unsafe-inline'"],
          // imgSrc: ["'self'", "data:"],
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
  const originsRaw = configService.get<string>('CORS_ORIGINS') ?? '';
  const origins = originsRaw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  app.enableCors({
    origin: origins.length ? origins : true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Authorization', 'Content-Type', 'Accept', 'X-CSRF-Token'],
    maxAge: 600,
    credentials: true, // <-- важно для cookie
  });

  // ---- validation ----
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true,
      forbidNonWhitelisted: true,
    }),
  );

  // ---- base settings ----

  app.setGlobalPrefix(apiPrefix);

  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: apiVersion,
  });

  // ---- swagger ----

  const { shouldEnableSwagger, apiBase } = setupSwagger(app, configService);

  // ---- start ----
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
    `❌ Failed to start application: ${err instanceof Error ? err.stack : String(err)}`,
  );
  process.exit(1);
});
