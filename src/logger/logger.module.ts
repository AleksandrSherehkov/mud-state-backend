import { Module } from '@nestjs/common';
import { AppLogger } from './logger.service';
import { ConfigModule, ConfigService } from '@nestjs/config';
import * as winston from 'winston';
import { createWinstonTransports } from './winston.config';

@Module({
  imports: [ConfigModule],
  providers: [
    {
      provide: AppLogger,
      useFactory: (config: ConfigService) => {
        const logger = winston.createLogger({
          level: config.get<string>('LOG_LEVEL', 'debug'),
          levels: winston.config.npm.levels,
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
