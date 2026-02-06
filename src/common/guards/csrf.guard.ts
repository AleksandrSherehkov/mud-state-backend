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

    if (isSafeMethod(req.method)) return true;

    const appEnv = (
      this.config.get<string>('APP_ENV') ?? 'development'
    ).toLowerCase();
    const isProd = appEnv === 'production';

    const csrf = splitOrigins(this.config.get<string>('CSRF_TRUSTED_ORIGINS'));
    const cors = splitOrigins(this.config.get<string>('CORS_ORIGINS'));

    const trusted = csrf.length > 0 ? csrf : cors;

    const originHeader = req.header('origin') || '';
    const refererHeader = req.header('referer') || '';

    const origin = originHeader ? parseOriginLike(originHeader) : null;
    const refererOrigin = refererHeader ? parseOriginLike(refererHeader) : null;

    const secFetchSite = (req.header('sec-fetch-site') || '').toLowerCase();

    const allowByFetchSite =
      secFetchSite === '' ||
      secFetchSite === 'same-origin' ||
      secFetchSite === 'same-site';

    const allowByOrigin =
      (origin && trusted.includes(origin)) ||
      (refererOrigin && trusted.includes(refererOrigin));

    if (isProd) {
      if (trusted.length === 0) {
        throw new ForbiddenException(
          'CSRF validation failed (trusted origins not configured)',
        );
      }

      if (!allowByFetchSite || !allowByOrigin) {
        throw new ForbiddenException('CSRF validation failed (origin)');
      }
    } else if (
      trusted.length > 0 &&
      (origin || refererOrigin) &&
      !allowByOrigin
    ) {
      throw new ForbiddenException('CSRF validation failed (origin)');
    }

    const csrfCookie = getCookieString(req, 'csrfToken');
    const csrfHeader = req.header('x-csrf-token');

    if (!csrfCookie || !csrfHeader || csrfCookie !== csrfHeader) {
      throw new ForbiddenException('CSRF validation failed');
    }

    return true;
  }
}
