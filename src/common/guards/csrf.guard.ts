import {
  CanActivate,
  ExecutionContext,
  Injectable,
  ForbiddenException,
} from '@nestjs/common';
import type { Request } from 'express';
import { ConfigService } from '@nestjs/config';
import { getCookieString } from 'src/common/http/cookies';

function isSafeMethod(method: string): boolean {
  const m = (method || '').toUpperCase();
  return m === 'GET' || m === 'HEAD' || m === 'OPTIONS';
}

function parseOriginLike(value: string): string | null {
  try {
    const u = new URL(value);
    return u.origin;
  } catch {
    return null;
  }
}

function splitOrigins(raw: string | undefined): string[] {
  return (raw ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

@Injectable()
export class CsrfGuard implements CanActivate {
  constructor(private readonly config: ConfigService) {}

  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest<Request>();

    // guard можна тримати універсальним: safe-methods не ламаємо
    if (isSafeMethod(req.method)) return true;

    // ---- 1) Origin/Referer allowlist (другий бар’єр) ----
    const appEnv = (
      this.config.get<string>('APP_ENV') ?? 'development'
    ).toLowerCase();
    const isProd = appEnv === 'production';

    // Рекомендується: окремо CSRF_TRUSTED_ORIGINS, але можна fallback на CORS_ORIGINS
    const csrf = splitOrigins(this.config.get<string>('CSRF_TRUSTED_ORIGINS'));
    const cors = splitOrigins(this.config.get<string>('CORS_ORIGINS'));

    const trusted = csrf.length > 0 ? csrf : cors;

    // у JS-клієнтів майже завжди буде Origin; для форм може бути Referer
    const originHeader = req.header('origin') || '';
    const refererHeader = req.header('referer') || '';

    const origin = originHeader ? parseOriginLike(originHeader) : null;
    const refererOrigin = refererHeader ? parseOriginLike(refererHeader) : null;

    // додатковий сучасний сигнал (не заміна allowlist, але корисний)
    const secFetchSite = (req.header('sec-fetch-site') || '').toLowerCase();

    const allowByFetchSite =
      secFetchSite === '' || // деякі клієнти/проксі можуть не передавати
      secFetchSite === 'same-origin' ||
      secFetchSite === 'same-site';

    const allowByOrigin =
      (origin && trusted.includes(origin)) ||
      (refererOrigin && trusted.includes(refererOrigin));

    // В prod краще fail-closed: якщо немає allowlist — краще 403, ніж “дірка”.
    if (isProd) {
      if (trusted.length === 0) {
        throw new ForbiddenException(
          'CSRF validation failed (trusted origins not configured)',
        );
      }
      if (!allowByFetchSite || !allowByOrigin) {
        throw new ForbiddenException('CSRF validation failed (origin)');
      }
    } else {
      // dev/test: м’якше — не валимо локальні запуски без Origin/Referer
      // але якщо Origin/Referer є — все одно перевіряємо, коли allowlist заданий
      if (trusted.length > 0 && (origin || refererOrigin)) {
        if (!allowByOrigin) {
          throw new ForbiddenException('CSRF validation failed (origin)');
        }
      }
    }

    // ---- 2) Double-submit (cookie == header) ----
    const csrfCookie = getCookieString(req, 'csrfToken');
    const csrfHeader = req.header('x-csrf-token');

    if (!csrfCookie || !csrfHeader || csrfCookie !== csrfHeader) {
      throw new ForbiddenException('CSRF validation failed');
    }

    return true;
  }
}
