import { Injectable, LoggerService, Scope } from '@nestjs/common';
import type { Logger as WinstonLogger } from 'winston';
import { sanitizeMeta, sanitizeString } from 'src/common/logging/log-sanitize';
import { getRequestId } from 'src/common/request-context/request-context';

type Meta = Record<string, unknown>;
type LogKind = 'operational' | 'audit';

@Injectable({ scope: Scope.TRANSIENT })
export class AppLogger implements LoggerService {
  constructor(private readonly winston: WinstonLogger) {}

  private context?: string;

  setContext(ctx: string) {
    this.context = ctx;
  }

  private withBaseMeta(meta?: Meta, logKind: LogKind = 'operational'): Meta {
    const requestId = getRequestId();
    const base: Meta = {
      logKind,
      ...(requestId ? { requestId } : {}),
    };

    const merged = meta ? { ...base, ...meta } : base;

    return sanitizeMeta(merged);
  }

  private safeMessage(message: unknown): string {
    const s = typeof message === 'string' ? message : String(message);
    return sanitizeString(s);
  }

  private safeContext(ctx?: string): string | undefined {
    const value = (ctx ?? this.context)?.trim();
    return value || undefined;
  }

  log(message: unknown, context?: string, meta?: Meta) {
    this.winston.info(this.safeMessage(message), {
      context: this.safeContext(context),
      ...this.withBaseMeta(meta, 'operational'),
    });
  }

  audit(message: unknown, context?: string, meta?: Meta) {
    this.winston.info(this.safeMessage(message), {
      context: this.safeContext(context),
      ...this.withBaseMeta(meta, 'audit'),
    });
  }

  error(message: unknown, trace?: string, context?: string, meta?: Meta) {
    const safeTrace = trace ? sanitizeString(trace) : undefined;

    this.winston.error(this.safeMessage(message), {
      context: this.safeContext(context),
      ...(safeTrace ? { trace: safeTrace } : {}),
      ...this.withBaseMeta(meta, 'operational'),
    });
  }

  warn(message: unknown, context?: string, meta?: Meta) {
    this.winston.warn(this.safeMessage(message), {
      context: this.safeContext(context),
      ...this.withBaseMeta(meta, 'operational'),
    });
  }

  debug(message: unknown, context?: string, meta?: Meta) {
    this.winston.debug(this.safeMessage(message), {
      context: this.safeContext(context),
      ...this.withBaseMeta(meta, 'operational'),
    });
  }

  verbose(message: unknown, context?: string, meta?: Meta) {
    this.winston.verbose(this.safeMessage(message), {
      context: this.safeContext(context),
      ...this.withBaseMeta(meta, 'operational'),
    });
  }
}
