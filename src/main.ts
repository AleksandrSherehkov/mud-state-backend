import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';
import { ValidationPipe, VersioningType } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { NestExpressApplication } from '@nestjs/platform-express';
import { AppLogger } from './logger/logger.service';

import { bootstrapLogger } from './logger/bootstrap-logger';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  const logger = await app.resolve(AppLogger);

  app.useLogger(logger);

  app.set('trust proxy', true);

  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true,
      forbidNonWhitelisted: true,
    }),
  );

  const configService = app.get(ConfigService);
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

  const apiBase = `${baseUrl}/${apiPrefix}/v${apiVersion}`;

  const config = new DocumentBuilder()
    .setTitle('MUD-State API')
    .setDescription('API for the MUD simulation state backend')
    .setVersion('1.0')
    .addBearerAuth()
    .addServer(apiBase, `API v${apiVersion}`)
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup(`${apiPrefix}/docs`, app, document);

  const port = configService.get<number>('PORT', 3000);
  await app.listen(port);
  logger.log(`🚀 Server running at ${apiBase}`, 'Bootstrap');
  logger.log(`📚 Swagger docs at ${baseUrl}/${apiPrefix}/docs`, 'Bootstrap');
}
bootstrap().catch((err: unknown) => {
  bootstrapLogger.error(
    `❌ Failed to start application: ${err instanceof Error ? err.stack : String(err)}`,
  );
  process.exit(1);
});
