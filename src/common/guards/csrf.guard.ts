import {
  CanActivate,
  ExecutionContext,
  Injectable,
  ForbiddenException,
} from '@nestjs/common';
import type { Request } from 'express';
import { ConfigService } from '@nestjs/config';
import { getCookieString } from 'src/common/http/cookies';
import { timingSafeEqual, createPublicKey } from 'node:crypto';
import { verify, type JwtPayload } from 'jsonwebtoken';

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
      this.assertProdOriginOrMachineToken(req, trusted, signals);
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

  private allowNoOriginInProd(): boolean {
    return (
      String(this.config.get('CSRF_ALLOW_NO_ORIGIN') ?? '')
        .toLowerCase()
        .trim() === 'true'
    );
  }

  private assertProdOriginOrMachineToken(
    req: Request,
    trusted: string[],
    signals: OriginSignals,
  ): void {
    const hasOrigin = Boolean(signals.origin || signals.refererOrigin);
    const hasFetchSite = signals.secFetchSite !== '';

    if (hasOrigin) {
      this.assertProdTrustedOrigin(trusted, signals);
      this.assertProdFetchSiteIfPresent(signals);
      return;
    }

    if (hasFetchSite) {
      this.assertProdFetchSiteOnly(signals);
      return;
    }

    if (this.allowNoOriginInProd()) return;

    this.assertNonBrowserAllowedByMachineToken(req);
  }

  private assertProdTrustedOrigin(trusted: string[], signals: OriginSignals) {
    const allowByOrigin =
      (signals.origin && trusted.includes(signals.origin)) ||
      (signals.refererOrigin && trusted.includes(signals.refererOrigin));

    if (!allowByOrigin) {
      throw new ForbiddenException(
        'CSRF validation failed (origin_not_trusted)',
      );
    }
  }

  private assertProdFetchSiteIfPresent(signals: OriginSignals) {
    if (!signals.secFetchSite) return;

    const ok =
      signals.secFetchSite === 'same-origin' ||
      signals.secFetchSite === 'same-site';

    if (!ok) {
      throw new ForbiddenException('CSRF validation failed (fetch_site)');
    }
  }

  private assertProdFetchSiteOnly(signals: OriginSignals) {
    const ok =
      signals.secFetchSite === 'same-origin' ||
      signals.secFetchSite === 'same-site';

    if (!ok) {
      throw new ForbiddenException('CSRF validation failed (fetch_site_only)');
    }
  }

  private timingSafeEqualString(expected: string, provided: string): boolean {
    const a = Buffer.from(expected, 'utf8');
    const b = Buffer.from(provided, 'utf8');

    if (a.length !== b.length) {
      const dummy = Buffer.alloc(a.length);
      b.copy(dummy, 0, 0, Math.min(b.length, a.length));
      timingSafeEqual(a, dummy);
      return false;
    }

    return timingSafeEqual(a, b);
  }

  private assertNonBrowserAllowedByMachineToken(req: Request): void {
    const token = (req.header('x-csrf-machine-token') ?? '').trim();
    if (!token) {
      throw new ForbiddenException('CSRF validation failed (non-browser)');
    }

    const publicKey = this.getRequiredConfig('CSRF_MACHINE_TOKEN_PUBLIC_KEY');
    const issuer = this.getRequiredConfig('CSRF_MACHINE_TOKEN_ISSUER');
    const audience = this.getRequiredConfig('CSRF_MACHINE_TOKEN_AUDIENCE');
    const clockTolerance = Number(
      this.config.get('CSRF_MACHINE_TOKEN_CLOCK_TOLERANCE_SEC') ?? 15,
    );

    let payload: string | JwtPayload;
    try {
      payload = verify(token, createPublicKey(publicKey), {
        algorithms: ['RS256', 'ES256'],
        issuer,
        audience,
        clockTolerance,
      });
    } catch {
      throw new ForbiddenException('CSRF validation failed (machine_token)');
    }

    if (typeof payload === 'string') {
      throw new ForbiddenException('CSRF validation failed (machine_token)');
    }

    const scope = String(payload.scope ?? '').trim();
    const hasScope = scope
      .split(/\s+/)
      .some((s) => this.timingSafeEqualString(s, 'csrf:unsafe'));

    if (!hasScope) {
      throw new ForbiddenException('CSRF validation failed (machine_scope)');
    }
  }

  private getRequiredConfig(name: string): string {
    const value = (this.config.get<string>(name) ?? '').trim();
    if (!value) {
      throw new ForbiddenException(`CSRF validation failed (${name})`);
    }
    return value;
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
