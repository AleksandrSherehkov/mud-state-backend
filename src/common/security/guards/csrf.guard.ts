import {
  CanActivate,
  ExecutionContext,
  Injectable,
  ForbiddenException,
} from '@nestjs/common';
import type { Request } from 'express';
import { ConfigService } from '@nestjs/config';
import { getCookieString } from 'src/common/http/cookies';
import { createHmac, timingSafeEqual } from 'node:crypto';
import Redis from 'ioredis';

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

type M2mClient = {
  kid: string;
  secret: string;
  scopes: string[]; // '*' or list of path prefixes
};

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

function base64Url(buf: Buffer): string {
  return buf
    .toString('base64')
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '');
}

@Injectable()
export class CsrfGuard implements CanActivate {
  private readonly redis: Redis;
  private readonly noncePrefix: string;

  constructor(private readonly config: ConfigService) {
    // ✅ reuse your existing Redis URL by default
    const url =
      (this.config.get<string>('CSRF_M2M_REDIS_URL') ?? '').trim() ||
      (this.config.get<string>('THROTTLE_REDIS_URL') ?? '').trim();

    if (!url) {
      // secure-by-default: in prod non-browser path will be denied anyway
      // but keep deterministic error for misconfig
      throw new Error('CSRF_M2M_REDIS_URL/THROTTLE_REDIS_URL is not set');
    }

    this.noncePrefix = (
      this.config.get<string>('CSRF_M2M_NONCE_PREFIX') ?? 'csrf:m2m:nonce:'
    ).trim();

    this.redis = new Redis(url, {
      lazyConnect: true,
      enableOfflineQueue: false,
      maxRetriesPerRequest: 1,
    });
  }

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const req = ctx.switchToHttp().getRequest<Request>();

    if (isSafeMethod(req.method)) return true;

    return this.validateUnsafeRequest(req);
  }

  private async validateUnsafeRequest(req: Request): Promise<boolean> {
    const isProd = this.isProdEnv();
    const trusted = this.getTrustedOrigins();
    const signals = this.getOriginSignals(req);

    if (isProd) {
      this.assertProdTrustedConfigured(trusted);
      await this.assertProdOriginOrM2m(req, trusted, signals);
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

  private async assertProdOriginOrM2m(
    req: Request,
    trusted: string[],
    signals: OriginSignals,
  ): Promise<void> {
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

    // ✅ NON-BROWSER M2M proof (HMAC + replay protection in Redis)
    await this.assertNonBrowserAllowedByHmac(req);
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

  private getM2mReplayWindowSec(): number {
    const v = Number(
      this.config.get<string>('CSRF_M2M_REPLAY_WINDOW_SEC') ?? 60,
    );
    if (!Number.isFinite(v) || v < 10 || v > 300) return 60;
    return Math.floor(v);
  }

  private parseM2mClients(): M2mClient[] {
    // Format:
    // CSRF_M2M_CLIENTS="kid1:secret1:/api|/internal; kid2:secret2:*"
    const raw = (this.config.get<string>('CSRF_M2M_CLIENTS') ?? '').trim();
    if (!raw) return [];

    return raw
      .split(/[;,]/g)
      .map((x) => x.trim())
      .filter(Boolean)
      .map((entry) => {
        const [kid, secret, scopesRaw] = entry.split(':');
        const k = (kid ?? '').trim();
        const s = (secret ?? '').trim();
        const scopes = (scopesRaw ?? '').trim();

        if (!k || !s) return null;

        const scopesList =
          !scopes || scopes === '*'
            ? ['*']
            : scopes
                .split('|')
                .map((p) => p.trim())
                .filter(Boolean);

        return { kid: k, secret: s, scopes: scopesList };
      })
      .filter((x): x is M2mClient => Boolean(x));
  }

  private assertM2mScopeAllowed(client: M2mClient, req: Request): void {
    if (client.scopes.includes('*')) return;

    const path = req.path || '';
    const ok = client.scopes.some(
      (prefix) => prefix && path.startsWith(prefix),
    );
    if (!ok) {
      throw new ForbiddenException('CSRF validation failed (m2m_scope)');
    }
  }

  private async assertRedisNonceOnce(
    key: string,
    ttlSec: number,
  ): Promise<void> {
    try {
      await this.redis.connect().catch(() => undefined);

      // SET key value NX EX ttl
      const res = await this.redis.set(key, '1', 'EX', ttlSec, 'NX');
      if (res !== 'OK') {
        throw new ForbiddenException('CSRF validation failed (m2m_replay)');
      }
    } catch (e) {
      // secure-by-default: if redis is down, deny non-browser bypass
      if (e instanceof ForbiddenException) throw e;
      throw new ForbiddenException('CSRF validation failed (non-browser)');
    }
  }

  private async assertNonBrowserAllowedByHmac(req: Request): Promise<void> {
    const kid = (req.header('x-csrf-m2m-kid') ?? '').trim();
    const tsRaw = (req.header('x-csrf-m2m-ts') ?? '').trim();
    const nonce = (req.header('x-csrf-m2m-nonce') ?? '').trim();
    const sign = (req.header('x-csrf-m2m-sign') ?? '').trim();

    if (!kid || !tsRaw || !nonce || !sign) {
      throw new ForbiddenException('CSRF validation failed (non-browser)');
    }

    if (!/^[a-zA-Z0-9_-]{1,32}$/.test(kid)) {
      throw new ForbiddenException('CSRF validation failed (m2m_kid)');
    }
    if (!/^[a-zA-Z0-9_-]{16,128}$/.test(nonce)) {
      throw new ForbiddenException('CSRF validation failed (m2m_nonce)');
    }

    const ts = Number(tsRaw);
    if (!Number.isFinite(ts) || !Number.isInteger(ts)) {
      throw new ForbiddenException('CSRF validation failed (m2m_ts)');
    }

    const windowSec = this.getM2mReplayWindowSec();
    const drift = Math.abs(nowSec() - ts);
    if (drift > windowSec) {
      throw new ForbiddenException('CSRF validation failed (m2m_ts_window)');
    }

    const clients = this.parseM2mClients();
    const client = clients.find((c) => c.kid === kid);
    if (!client) {
      throw new ForbiddenException('CSRF validation failed (non-browser)');
    }

    this.assertM2mScopeAllowed(client, req);

    // ✅ Redis replay protection (kid+ts+nonce)
    const replayKey = `${this.noncePrefix}${kid}:${ts}:${nonce}`;
    await this.assertRedisNonceOnce(replayKey, windowSec);

    // signature over stable canonical string binds request target
    const canonical = `${kid}.${ts}.${nonce}.${req.method.toUpperCase()}.${req.originalUrl}`;
    const expected = base64Url(
      createHmac('sha256', client.secret).update(canonical).digest(),
    );

    const ok =
      expected.length > 0 &&
      sign.length > 0 &&
      this.timingSafeEqualString(expected, sign);

    if (!ok) {
      // best-effort delete to not burn nonce on invalid signatures
      try {
        await this.redis.del(replayKey);
      } catch {
        // ignore
      }
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

    const ok =
      Boolean(csrfCookie && csrfHeader) &&
      this.timingSafeEqualString(csrfCookie!, csrfHeader!);

    if (!ok) throw new ForbiddenException('CSRF validation failed');

    return true;
  }
}
