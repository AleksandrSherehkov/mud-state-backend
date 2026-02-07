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

type OriginSignals = {
  origin: string | null;
  refererOrigin: string | null;
  secFetchSite: string;
};

@Injectable()
export class CsrfGuard implements CanActivate {
  constructor(private readonly config: ConfigService) {}

  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest<Request>();

    return isSafeMethod(req.method) || this.validateUnsafeRequest(req);
  }

  private validateUnsafeRequest(req: Request): boolean {
    const isProd = this.isProdEnv();
    const trusted = this.getTrustedOrigins();
    const signals = this.getOriginSignals(req);

    if (isProd) {
      this.assertProdTrustedConfigured(trusted);
      this.assertProdOriginOrApiKey(req, trusted, signals);
    } else {
      this.assertNonProdOriginIfPresent(trusted, signals);
    }

    return this.isDoubleSubmitValid(req);
  }

  private isProdEnv(): boolean {
    const appEnv = (this.config.get<string>('APP_ENV') ?? 'development')
      .toLowerCase()
      .trim();
    return appEnv === 'production';
  }

  private getTrustedOrigins(): string[] {
    const csrf = splitOrigins(this.config.get<string>('CSRF_TRUSTED_ORIGINS'));
    if (csrf.length > 0) return csrf;

    const cors = splitOrigins(this.config.get<string>('CORS_ORIGINS'));
    return cors;
  }

  private getOriginSignals(req: Request): OriginSignals {
    const originHeader = req.header('origin') || '';
    const refererHeader = req.header('referer') || '';

    const origin = originHeader ? parseOriginLike(originHeader) : null;
    const refererOrigin = refererHeader ? parseOriginLike(refererHeader) : null;

    const secFetchSite = (req.header('sec-fetch-site') || '').toLowerCase();

    return { origin, refererOrigin, secFetchSite };
  }

  private assertProdTrustedConfigured(trusted: string[]): void {
    if (trusted.length === 0) {
      throw new ForbiddenException(
        'CSRF validation failed (trusted origins not configured)',
      );
    }
  }

  private assertProdOriginOrApiKey(
    req: Request,
    trusted: string[],
    signals: OriginSignals,
  ): void {
    const hasOriginSignals = Boolean(
      signals.origin || signals.refererOrigin || signals.secFetchSite,
    );

    if (hasOriginSignals) {
      this.assertProdOriginValid(trusted, signals);
      return;
    }

    this.assertNonBrowserAllowedByApiKey(req);
  }

  private assertProdOriginValid(
    trusted: string[],
    signals: OriginSignals,
  ): void {
    const allowByFetchSite =
      signals.secFetchSite === '' ||
      signals.secFetchSite === 'same-origin' ||
      signals.secFetchSite === 'same-site';

    const allowByOrigin =
      (signals.origin && trusted.includes(signals.origin)) ||
      (signals.refererOrigin && trusted.includes(signals.refererOrigin));

    if (!allowByFetchSite || !allowByOrigin) {
      throw new ForbiddenException('CSRF validation failed (origin)');
    }
  }

  private assertNonBrowserAllowedByApiKey(req: Request): void {
    const configuredApiKey = (
      this.config.get<string>('CSRF_API_KEY') ?? ''
    ).trim();
    const requestApiKey = (req.header('x-csrf-api-key') ?? '').trim();

    const allow =
      configuredApiKey.length > 0 &&
      requestApiKey.length > 0 &&
      requestApiKey === configuredApiKey;

    if (!allow) {
      throw new ForbiddenException('CSRF validation failed (non-browser)');
    }
  }

  private assertNonProdOriginIfPresent(
    trusted: string[],
    signals: OriginSignals,
  ): void {
    if (trusted.length === 0) return;

    const hasOrigin = Boolean(signals.origin || signals.refererOrigin);
    if (!hasOrigin) return;

    const allowByOrigin =
      (signals.origin && trusted.includes(signals.origin)) ||
      (signals.refererOrigin && trusted.includes(signals.refererOrigin));

    if (!allowByOrigin) {
      throw new ForbiddenException('CSRF validation failed (origin)');
    }
  }

  private isDoubleSubmitValid(req: Request): boolean {
    const csrfCookie = getCookieString(req, 'csrfToken');
    const csrfHeader = req.header('x-csrf-token');

    const ok = Boolean(csrfCookie && csrfHeader && csrfCookie === csrfHeader);
    if (!ok) throw new ForbiddenException('CSRF validation failed');

    return true;
  }
}
