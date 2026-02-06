import { Module } from '@nestjs/common';
import { AppLogger } from './logger.service';
import { ConfigModule, ConfigService } from '@nestjs/config';
import * as winston from 'winston';
import { createWinstonTransports } from './winston.config';

function resolveLevel(config: ConfigService): string {
  const explicit = config.get<string>('LOG_LEVEL');
  if (explicit) return explicit;

  const env = (
    config.get<string>('APP_ENV', 'development') || 'development'
  ).toLowerCase();

  return env === 'production' ? 'info' : 'debug';
}

@Module({
  imports: [ConfigModule],
  providers: [
    {
      provide: AppLogger,
      useFactory: (config: ConfigService) => {
        const logger = winston.createLogger({
          level: resolveLevel(config),
          levels: winston.config.npm.levels,

          // ❗️ВАЖЛИВО: НЕ задаємо format глобально
          // Увесь format (sanitize/timestamp/printf/json) буде в transport-ах
          transports: createWinstonTransports(config),
        });

        return new AppLogger(logger);
      },
      inject: [ConfigService],
    },
  ],
  exports: [AppLogger],
})
export class LoggerModule {}
