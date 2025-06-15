import { Injectable, LoggerService, Scope } from '@nestjs/common';
import * as winston from 'winston';
import 'winston-daily-rotate-file';
import { consoleTransport, fileTransport } from './winston.config';

const baseLogger = winston.createLogger({
  level: 'debug',
  levels: winston.config.npm.levels,
  transports: [consoleTransport, fileTransport],
});

@Injectable({ scope: Scope.TRANSIENT })
export class AppLogger implements LoggerService {
  private context?: string;

  setContext(context: string) {
    this.context = context;
  }

  log(message: string, context?: string) {
    baseLogger.info(message, { context: context || this.context });
  }

  error(message: string, trace?: string, context?: string) {
    baseLogger.error(message, { context: context || this.context, trace });
  }

  warn(message: string, context?: string) {
    baseLogger.warn(message, { context: context || this.context });
  }

  debug(message: string, context?: string) {
    baseLogger.debug(message, { context: context || this.context });
  }
}
