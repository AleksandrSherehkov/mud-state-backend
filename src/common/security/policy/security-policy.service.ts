import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { FetchSiteValue, SecurityPolicy } from './security-policy.types';

function splitList(raw: string | undefined): string[] {
  return (raw ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function boolFromConfig(
  config: ConfigService,
  key: string,
  def = false,
): boolean {
  const v = String(config.get(key) ?? '')
    .trim()
    .toLowerCase();
  if (!v) return def;
  return v === '1' || v === 'true' || v === 'yes' || v === 'on';
}

function clampInt(v: number, min: number, max: number, def: number): number {
  if (!Number.isFinite(v)) return def;
  const n = Math.floor(v);
  if (n < min || n > max) return def;
  return n;
}

function isFetchSiteValue(v: string): v is FetchSiteValue {
  return v === 'same-origin' || v === 'same-site';
}

@Injectable()
export class SecurityPolicyService {
  private readonly snapshot: SecurityPolicy;

  constructor(private readonly config: ConfigService) {
    this.snapshot = this.buildPolicy();
  }

  get(): SecurityPolicy {
    return this.snapshot;
  }

  private buildPolicy(): SecurityPolicy {
    const appEnvRaw = String(this.config.get('APP_ENV') ?? 'development')
      .trim()
      .toLowerCase();

    const appEnv =
      appEnvRaw === 'production' || appEnvRaw === 'test'
        ? appEnvRaw
        : 'development';

    const isProd = appEnv === 'production';

    const csrfTrusted = splitList(
      this.config.get<string>('CSRF_TRUSTED_ORIGINS'),
    );
    const corsOrigins = splitList(this.config.get<string>('CORS_ORIGINS'));
    const trustedOrigins = csrfTrusted.length > 0 ? csrfTrusted : corsOrigins;

    const allowNoOriginInProd = boolFromConfig(
      this.config,
      'CSRF_ALLOW_NO_ORIGIN',
      false,
    );

    const replayWindowSec = clampInt(
      Number(this.config.get('CSRF_M2M_REPLAY_WINDOW_SEC') ?? 60),
      10,
      300,
      60,
    );

    const m2mEnabled = boolFromConfig(this.config, 'CSRF_M2M_ENABLED', true);

    const redisUrl =
      String(this.config.get('CSRF_M2M_REDIS_URL') ?? '').trim() ||
      String(this.config.get('THROTTLE_REDIS_URL') ?? '').trim();

    if (m2mEnabled && !redisUrl) {
      throw new Error('Redis URL is required for CSRF M2M replay protection');
    }

    const noncePrefix =
      String(
        this.config.get('CSRF_M2M_NONCE_PREFIX') ?? 'csrf:m2m:nonce:',
      ).trim() || 'csrf:m2m:nonce:';

    const allowedFetchSitesRaw = splitList(
      String(
        this.config.get('CSRF_ALLOWED_FETCH_SITES') ?? 'same-origin,same-site',
      ),
    )
      .map((x) => x.toLowerCase())
      .filter(Boolean)
      .filter(isFetchSiteValue);

    const allowedFetchSites: FetchSiteValue[] =
      allowedFetchSitesRaw.length > 0
        ? allowedFetchSitesRaw
        : ['same-origin', 'same-site'];

    const secretsFile =
      String(this.config.get('CSRF_M2M_SECRETS_FILE') ?? '').trim() ||
      undefined;

    const reloadTtlSec = clampInt(
      Number(this.config.get('CSRF_M2M_SECRETS_RELOAD_TTL_SEC') ?? 30),
      1,
      3600,
      30,
    );

    return {
      appEnv,
      isProd,

      csrf: {
        enabled: boolFromConfig(this.config, 'CSRF_ENABLED', true),

        cookieName:
          String(this.config.get('CSRF_COOKIE_NAME') ?? 'csrfToken').trim() ||
          'csrfToken',

        headerName:
          String(this.config.get('CSRF_HEADER_NAME') ?? 'x-csrf-token')
            .trim()
            .toLowerCase() || 'x-csrf-token',

        trustedOrigins,
        allowNoOriginInProd,

        enforceFetchSiteInProd: boolFromConfig(
          this.config,
          'CSRF_ENFORCE_FETCH_SITE_IN_PROD',
          true,
        ),
        allowedFetchSites,

        m2m: {
          enabled: m2mEnabled,
          replayWindowSec,
          redisUrl,
          noncePrefix,
          secretsFile,
          reloadTtlSec,
        },
      },

      proxyGeoTrust: {
        enabled: boolFromConfig(this.config, 'TRUST_PROXY_GEO_HEADERS', false),
        trustedProxyIps: splitList(
          this.config.get<string>('TRUSTED_PROXY_IPS'),
        ),
        markerName:
          String(
            this.config.get('TRUST_PROXY_GEO_MARKER_NAME') ?? 'x-ingress-auth',
          )
            .trim()
            .toLowerCase() || 'x-ingress-auth',
        markerValue:
          String(
            this.config.get('TRUST_PROXY_GEO_MARKER_VALUE') ?? '1',
          ).trim() || '1',
      },
    };
  }
}
