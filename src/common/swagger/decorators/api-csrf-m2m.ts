import { applyDecorators } from '@nestjs/common';
import { ApiCookieAuth, ApiHeader, ApiSecurity } from '@nestjs/swagger';

type CsrfM2mOptions = {
  includeRefreshCookie?: boolean;
};

export function ApiCsrfM2mProtected(opts: CsrfM2mOptions = {}) {
  const includeRefreshCookie = Boolean(opts.includeRefreshCookie);

  return applyDecorators(
    ...(includeRefreshCookie ? [ApiCookieAuth('refresh_cookie')] : []),

    ApiCookieAuth('csrf_cookie'),

    ApiSecurity('csrf_header'),
    ApiSecurity('csrf_m2m_kid'),
    ApiSecurity('csrf_m2m_ts'),
    ApiSecurity('csrf_m2m_nonce'),
    ApiSecurity('csrf_m2m_sign'),

    ApiHeader({
      name: 'X-CSRF-Token',
      required: true,
      description:
        'CSRF token (повинен збігатися зі значенням cookie csrfToken)',
    }),

    ApiHeader({
      name: 'X-CSRF-M2M-Kid',
      required: false,
      description: 'M2M key id (kid) for CSRF HMAC proof (non-browser only).',
    }),
    ApiHeader({
      name: 'X-CSRF-M2M-TS',
      required: false,
      description: 'Unix timestamp (seconds) within replay window.',
    }),
    ApiHeader({
      name: 'X-CSRF-M2M-Nonce',
      required: false,
      description: 'Unique nonce (replay-protected) within replay window.',
    }),
    ApiHeader({
      name: 'X-CSRF-M2M-Sign',
      required: false,
      description:
        'base64url(HMAC-SHA256(secret, `${kid}.${ts}.${nonce}.${METHOD}.${originalUrl}`))',
    }),
  );
}
