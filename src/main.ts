import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';
import { ValidationPipe } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { NestExpressApplication } from '@nestjs/platform-express';
import { AppLogger } from './logger/logger.service';
import * as morgan from 'morgan';
import { bootstrapLogger } from './logger/bootstrap-logger';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  const logger = await app.resolve(AppLogger);
  logger.setContext('Bootstrap');
  app.useLogger(logger);

  app.use(
    morgan('combined', {
      stream: {
        write: (message) => logger.log(message.trim(), 'HTTP'),
      },
    }),
  );

  app.set('trust proxy', true);

  app.setGlobalPrefix('api');

  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true,
      forbidNonWhitelisted: true,
    }),
  );

  const configService = app.get(ConfigService);
  const baseUrl =
    configService.get<string>('BASE_URL') ?? 'http://localhost:3000';

  const config = new DocumentBuilder()
    .setTitle('MUD-State API')
    .setDescription('API for the MUD simulation state backend')
    .setVersion('1.0')
    .addBearerAuth()
    .addServer(baseUrl, 'Local server')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document);

  const port = configService.get<number>('PORT', 3000);
  await app.listen(port);
  logger.log(`🚀 Server running at ${baseUrl}/api`);
  logger.log(`📚 Swagger docs at ${baseUrl}/api/docs`);
}
bootstrap().catch((err: unknown) => {
  bootstrapLogger.error(
    `❌ Failed to start application: ${err instanceof Error ? err.stack : String(err)}`,
  );
  process.exit(1);
});
