import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';
import { VersioningType } from '@nestjs/common';
import { NestExpressApplication } from '@nestjs/platform-express';
import { useContainer } from 'class-validator';

import { AppLogger } from './logger/logger.service';
import { bootstrapLogger } from './logger/bootstrap-logger';

import { setupSwagger } from './common/swagger/setup-swagger';

import {
  validateSecurityConfig,
  checkRedisOrThrow,
  applyHelmet,
  applyCors,
  applyCookieParser,
  applyValidation,
} from './common/bootstrap';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  useContainer(app.select(AppModule), { fallbackOnErrors: true });

  const logger = await app.resolve(AppLogger);
  app.useLogger(logger);

  const config = app.get(ConfigService);

  const apiPrefix = config.get<string>('API_PREFIX', 'api');
  const apiVersion = config.get<string>('API_VERSION', '1');
  const baseUrl = config.get<string>('BASE_URL', 'http://localhost:3000');

  const appEnv = config.get<string>('APP_ENV') ?? 'development';
  const isProd = appEnv === 'production';

  const trustProxy = Number(config.get('TRUST_PROXY_HOPS') ?? 1);
  app.set('trust proxy', trustProxy);

  // ---- SECURITY CONFIG VALIDATION ----
  validateSecurityConfig(config);

  // ---- Redis health-check (throttling backend is always Redis) ----
  await checkRedisOrThrow(config, logger);

  // ---- Swagger ----
  const { shouldEnableSwagger, apiBase } = setupSwagger(app, config);

  // ---- HTTP security middleware ----
  applyHelmet(app, config, { shouldEnableSwagger, isProd });
  applyCookieParser(app, config);
  applyCors(app, config, { isProd });
  applyValidation(app);

  // ---- Routing ----
  app.setGlobalPrefix(apiPrefix);
  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: apiVersion,
  });

  const port = config.get<number>('PORT', 3000);
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
