import { Injectable, LoggerService, Scope } from '@nestjs/common';
import * as winston from 'winston';
import { sanitizeMeta } from 'src/common/helpers/log-sanitize';
import { getRequestId } from 'src/common/request-context/request-context';

type Meta = Record<string, unknown>;

@Injectable({ scope: Scope.TRANSIENT })
export class AppLogger implements LoggerService {
  private context?: string;

  constructor(private readonly logger: winston.Logger) {}

  setContext(context: string) {
    this.context = context || 'App';
  }

  private base(context?: string, meta?: Meta): Meta {
    const requestId = getRequestId();

    const merged: Meta = {
      ...(meta ?? {}),
      context: context || this.context || 'App',
      ...(requestId ? { requestId } : {}),
    };

    return sanitizeMeta(merged);
  }

  log(message: string, context?: string, meta?: Meta) {
    this.logger.info(message, this.base(context, meta));
  }

  warn(message: string, context?: string, meta?: Meta) {
    this.logger.warn(message, this.base(context, meta));
  }

  debug(message: string, context?: string, meta?: Meta) {
    this.logger.debug(message, this.base(context, meta));
  }

  verbose(message: string, context?: string, meta?: Meta) {
    this.logger.verbose(message, this.base(context, meta));
  }

  silly(message: string, context?: string, meta?: Meta) {
    this.logger.silly(message, this.base(context, meta));
  }

  error(message: string, trace?: string, context?: string, meta?: Meta) {
    const base = this.base(context, meta);
    this.logger.error(message, { ...base, trace });
  }
}
