// src/logger/logger.service.ts
import { Injectable, LoggerService, Scope } from '@nestjs/common';
import type { Logger as WinstonLogger } from 'winston';
import { sanitizeMeta, sanitizeString } from 'src/common/helpers/log-sanitize';
import { getRequestId } from 'src/common/request-context/request-context';

type Meta = Record<string, unknown>;

@Injectable({ scope: Scope.TRANSIENT })
export class AppLogger implements LoggerService {
  // ВАЖЛИВО: цей winston-інстанс має бути створений у LoggerModule
  // і інжектитись сюди (як у тебе зараз).
  constructor(private readonly winston: WinstonLogger) {}

  private context?: string;

  setContext(ctx: string) {
    this.context = ctx;
  }

  // ---- centralized sanitization ----
  private withBaseMeta(meta?: Meta): Meta {
    const requestId = getRequestId();
    const base: Meta = {
      ...(requestId ? { requestId } : {}),
    };

    // 1) об’єднали meta
    const merged = meta ? { ...base, ...meta } : base;

    // 2) санітизували ВСЕ
    return sanitizeMeta(merged);
  }

  private safeMessage(message: unknown): string {
    const s = typeof message === 'string' ? message : String(message);
    return sanitizeString(s);
  }

  private safeContext(ctx?: string): string | undefined {
    const c = (ctx ?? this.context)?.trim();
    return c ? c : undefined;
  }

  log(message: unknown, context?: string, meta?: Meta) {
    this.winston.info(this.safeMessage(message), {
      context: this.safeContext(context),
      ...this.withBaseMeta(meta),
    });
  }

  error(message: unknown, trace?: string, context?: string, meta?: Meta) {
    // trace теж може містити токени (рідко, але буває) — санітизуємо
    const safeTrace = trace ? sanitizeString(trace) : undefined;

    this.winston.error(this.safeMessage(message), {
      context: this.safeContext(context),
      ...(safeTrace ? { trace: safeTrace } : {}),
      ...this.withBaseMeta(meta),
    });
  }

  warn(message: unknown, context?: string, meta?: Meta) {
    this.winston.warn(this.safeMessage(message), {
      context: this.safeContext(context),
      ...this.withBaseMeta(meta),
    });
  }

  debug(message: unknown, context?: string, meta?: Meta) {
    this.winston.debug(this.safeMessage(message), {
      context: this.safeContext(context),
      ...this.withBaseMeta(meta),
    });
  }

  verbose(message: unknown, context?: string, meta?: Meta) {
    this.winston.verbose(this.safeMessage(message), {
      context: this.safeContext(context),
      ...this.withBaseMeta(meta),
    });
  }
}
