import { ConfigService } from '@nestjs/config';
import { parseList } from './parse-list';

function normalizeEnvFlag(value: unknown): string {
  if (typeof value === 'string') {
    return value.trim().toLowerCase();
  }

  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value).trim().toLowerCase();
  }

  return '';
}

function isTrueLike(value: unknown): boolean {
  const raw = normalizeEnvFlag(value);
  return raw === 'true' || raw === '1' || raw === 'yes' || raw === 'on';
}

function assertDistinctJwtSecrets(config: ConfigService): void {
  const accessSecret = String(config.get('JWT_ACCESS_SECRET') ?? '').trim();
  const refreshSecret = String(config.get('JWT_REFRESH_SECRET') ?? '').trim();

  if (accessSecret && refreshSecret && accessSecret === refreshSecret) {
    throw new Error(
      'SECURITY: JWT_ACCESS_SECRET must not equal JWT_REFRESH_SECRET (separate secrets required)',
    );
  }
}

function assertDummyPasswordHash(isProd: boolean, config: ConfigService): void {
  if (!isProd) return;

  const hash = String(config.get('AUTH_DUMMY_PASSWORD_HASH') ?? '').trim();

  if (!hash) {
    throw new Error(
      'SECURITY: AUTH_DUMMY_PASSWORD_HASH must be set in production',
    );
  }
}

function assertCorsConfig(isProd: boolean, corsOrigins: string[]): void {
  if (isProd && corsOrigins.length === 0) {
    throw new Error('SECURITY: CORS_ORIGINS має бути визначено у production');
  }

  if (corsOrigins.includes('*')) {
    throw new Error(
      'SECURITY: wildcard CORS (*) заборонено (і несумісно з credentials=true)',
    );
  }
}

function assertTrustProxy(
  isProd: boolean,
  trustProxyRaw: string | undefined,
): void {
  if (!isProd) return;

  const trustProxy = Number(trustProxyRaw ?? 1);
  const ok =
    Number.isInteger(trustProxy) && trustProxy >= 1 && trustProxy <= 10;

  if (!ok) {
    throw new Error(
      'SECURITY: TRUST_PROXY_HOPS має бути цілим числом 1..10 у production (щоб req.ip був реальним клієнтом за проксі)',
    );
  }
}

function assertCsrfNoOriginPolicy(
  isProd: boolean,
  csrfAllowNoOriginRaw: unknown,
): void {
  if (!isProd) return;

  if (isTrueLike(csrfAllowNoOriginRaw)) {
    throw new Error(
      'SECURITY: CSRF_ALLOW_NO_ORIGIN=true is forbidden in production. Use explicit CSRF M2M HMAC flow for controlled non-browser clients.',
    );
  }
}

function assertSameSiteNonePolicy(
  baseUrl: string,
  cookieSameSite: string | undefined,
  cookieCrossSite: boolean | undefined,
  corsOrigins: string[],
): void {
  if (cookieSameSite !== 'none') return;

  if (!baseUrl.startsWith('https://')) {
    throw new Error(
      'SECURITY: COOKIE_SAMESITE=none вимагає HTTPS BASE_URL у production',
    );
  }

  if (!cookieCrossSite) {
    throw new Error(
      'SECURITY: COOKIE_SAMESITE=none вимагає увімкнення COOKIE_CROSS_SITE=true',
    );
  }

  if (corsOrigins.some((o) => o.startsWith('http://'))) {
    throw new Error(
      'SECURITY: HTTP origins заборонені, коли увімкнено SameSite=None у production',
    );
  }
}

function assertNoLocalhostInProd(
  corsOrigins: string[],
  csrfOrigins: string[],
): void {
  const corsHasLocalhost = corsOrigins.some((o) => o.includes('localhost'));
  const csrfHasLocalhost = csrfOrigins.some((o) => o.includes('localhost'));

  if (corsHasLocalhost || csrfHasLocalhost) {
    throw new Error('SECURITY: localhost origins заборонені у production');
  }
}

export function validateSecurityConfig(config: ConfigService) {
  const appEnv = config.get<string>('APP_ENV') ?? 'development';
  const isProd = appEnv === 'production';

  assertDistinctJwtSecrets(config);
  assertDummyPasswordHash(isProd, config);

  const baseUrl = config.get<string>('BASE_URL', 'http://localhost:3000');
  const cookieSameSite = config.get<string>('COOKIE_SAMESITE');
  const cookieCrossSite = config.get<boolean>('COOKIE_CROSS_SITE');

  const corsOrigins = parseList(config.get<string>('CORS_ORIGINS'));
  const csrfOrigins = parseList(config.get<string>('CSRF_TRUSTED_ORIGINS'));

  assertCorsConfig(isProd, corsOrigins);
  assertTrustProxy(isProd, config.get<string>('TRUST_PROXY_HOPS'));
  assertCsrfNoOriginPolicy(isProd, config.get('CSRF_ALLOW_NO_ORIGIN'));

  if (!isProd) return;

  assertSameSiteNonePolicy(
    baseUrl,
    cookieSameSite,
    cookieCrossSite,
    corsOrigins,
  );
  assertNoLocalhostInProd(corsOrigins, csrfOrigins);
}
