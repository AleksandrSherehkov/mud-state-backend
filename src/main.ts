import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';
import { ValidationPipe, Logger } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { NestExpressApplication } from '@nestjs/platform-express';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

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
    .addBearerAuth() // Authorization: Bearer <token>
    .addServer(baseUrl, 'Local server')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document);

  const port = configService.get<number>('PORT', 3000);
  await app.listen(port);
  Logger.log(`🚀 Server running at ${baseUrl}/api`);
  Logger.log(`📚 Swagger docs at ${baseUrl}/api/docs`);
}
bootstrap().catch((err) => {
  Logger.error('❌ Failed to start application:', err);
  process.exit(1);
});
