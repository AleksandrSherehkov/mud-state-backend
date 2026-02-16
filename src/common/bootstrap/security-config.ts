import { ConfigService } from '@nestjs/config';
import { parseList } from './parse-list';

export function validateSecurityConfig(config: ConfigService) {
  const appEnv = config.get<string>('APP_ENV') ?? 'development';
  const isProd = appEnv === 'production';

  const baseUrl = config.get<string>('BASE_URL', 'http://localhost:3000');

  const cookieSameSite = config.get<string>('COOKIE_SAMESITE');
  const cookieCrossSite = config.get<boolean>('COOKIE_CROSS_SITE');

  const corsOrigins = parseList(config.get<string>('CORS_ORIGINS'));
  const csrfOrigins = parseList(config.get<string>('CSRF_TRUSTED_ORIGINS'));

  if (isProd && corsOrigins.length === 0) {
    throw new Error('SECURITY: CORS_ORIGINS має бути визначено у production');
  }

  if (corsOrigins.includes('*')) {
    throw new Error(
      'SECURITY: wildcard CORS (*) заборонено (і несумісно з credentials=true)',
    );
  }

  const trustProxyRaw = config.get<string>('TRUST_PROXY_HOPS');
  const trustProxy = Number(trustProxyRaw ?? 1);

  if (isProd) {
    if (!Number.isInteger(trustProxy) || trustProxy < 1 || trustProxy > 10) {
      throw new Error(
        'SECURITY: TRUST_PROXY_HOPS має бути цілим числом 1..10 у production (щоб req.ip був реальним клієнтом за проксі)',
      );
    }
  }

  if (!isProd) return;

  if (cookieSameSite === 'none') {
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

  if (
    corsOrigins.some((o) => o.includes('localhost')) ||
    csrfOrigins.some((o) => o.includes('localhost'))
  ) {
    throw new Error('SECURITY: localhost origins заборонені у production');
  }
}
