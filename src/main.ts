import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';
import { ValidationPipe, VersioningType } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { NestExpressApplication } from '@nestjs/platform-express';
import { AppLogger } from './logger/logger.service';

import { bootstrapLogger } from './logger/bootstrap-logger';
import { useContainer } from 'class-validator';
import helmet from 'helmet';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  useContainer(app.select(AppModule), { fallbackOnErrors: true });

  const logger = await app.resolve(AppLogger);
  app.useLogger(logger);

  const configService = app.get(ConfigService);

  // ---- security middleware ----
  app.use(
    helmet({
      // CSP лучше включать точечно, когда будет понятна политика фронта/доменов
      contentSecurityPolicy: false,
      crossOriginResourcePolicy: { policy: 'same-site' },
    }),
  );

  // ---- CORS ----
  const originsRaw = configService.get<string>('CORS_ORIGINS') ?? '';
  const origins = originsRaw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  app.enableCors({
    origin: origins.length ? origins : false, // false = запретить если не задано
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Authorization', 'Content-Type', 'Accept'],
    maxAge: 600,
    credentials: false,
  });

  // ---- trust proxy ----
  app.set('trust proxy', Number(configService.get('TRUST_PROXY_HOPS') ?? 1));

  // ---- validation ----
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true,
      forbidNonWhitelisted: true,
    }),
  );

  // ---- base settings ----
  const baseUrl = configService.get<string>(
    'BASE_URL',
    'http://localhost:3000',
  );
  const apiPrefix = configService.get<string>('API_PREFIX', 'api');
  const apiVersion = configService.get<string>('API_VERSION', '1');

  app.setGlobalPrefix(apiPrefix);

  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: apiVersion,
  });

  // ---- swagger ----
  const appEnv = configService.get<string>('APP_ENV') ?? 'development';
  const swaggerEnabled = Boolean(configService.get<boolean>('SWAGGER_ENABLED'));

  const shouldEnableSwagger = swaggerEnabled && appEnv !== 'production';

  if (shouldEnableSwagger) {
    const config = new DocumentBuilder()
      .setTitle('MUD-State API')
      .setDescription('API for the MUD simulation state backend')
      .setVersion('1.0')
      .addBearerAuth()
      .addServer(baseUrl, 'Base server')
      .build();

    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup(`${apiPrefix}/docs`, app, document);
  }

  // ---- start ----
  const port = configService.get<number>('PORT', 3000);
  await app.listen(port);

  const apiBase = `${baseUrl}/${apiPrefix}/v${apiVersion}`;
  logger.log('==============================', 'Bootstrap');
  logger.log('✅ APP STARTED', 'Bootstrap');
  logger.log(`🔌 Listening on port: ${port}`, 'Bootstrap');
  logger.log(`🌍 ENV: ${appEnv}`, 'Bootstrap');
  logger.log(`🚀 Server: ${apiBase}`, 'Bootstrap');
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
