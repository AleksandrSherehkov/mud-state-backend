import type { INestApplication } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import type { ConfigService } from '@nestjs/config';

import { SecurityPolicyService } from 'src/common/security/policy/security-policy.service';
import {
  SWAGGER_CSRF_COOKIE_NAME_PLACEHOLDER,
  SWAGGER_CSRF_HEADER_NAME_PLACEHOLDER,
  SWAGGER_REFRESH_COOKIE_NAME_PLACEHOLDER,
} from './auth/auth.placeholders';
type SwaggerRuntimePolicy = {
  refreshCookieName: string;
  csrfCookieName: string;
  csrfHeaderName: string;
};

function buildSwaggerDescription(policy: SwaggerRuntimePolicy): string {
  return [
    'API для бекенду стану симуляції MUD.',
    '',
    'Модель автентифікації:',
    '- Access token: Bearer JWT у заголовку `Authorization`.',
    `- Refresh token: зберігається у cookie \`${policy.refreshCookieName}\` (HttpOnly, signed).`,
    '',
    'CSRF-захист (double-submit):',
    `- Cookie \`${policy.csrfCookieName}\` (не HttpOnly, короткоживуча) + заголовок \`${policy.csrfHeaderName}\`.`,
    '- Обовʼязковий для ВСІХ ендпоінтів, які встановлюють / оновлюють / очищають auth cookies:',
    '  - POST /auth/register',
    '  - POST /auth/login',
    '  - POST /auth/refresh',
    '  - POST /auth/logout',
    '',
    'Ініціалізація CSRF cookie:',
    `- GET /auth/csrf встановлює або оновлює cookie \`${policy.csrfCookieName}\` (15 хвилин).`,
    '',
    'Ротація токенів:',
    `- POST /auth/refresh оновлює лише cookie \`${policy.refreshCookieName}\`.`,
    `- \`${policy.csrfCookieName}\` cookie залишається без змін і може бути перевидана окремо через GET /auth/csrf.`,
    '',
    'Примітки:',
    '- Cookies потребують `credentials: true` у CORS та коректних налаштувань `SameSite` / `Secure`.',
    '- У production режимі `SameSite=None` вимагає `Secure=true` (HTTPS).',
  ].join('\n');
}

function applySwaggerRuntimePolicy<T>(
  document: T,
  policy: SwaggerRuntimePolicy,
): T {
  const patched = JSON.stringify(document)
    .replaceAll(
      SWAGGER_REFRESH_COOKIE_NAME_PLACEHOLDER,
      policy.refreshCookieName,
    )
    .replaceAll(SWAGGER_CSRF_COOKIE_NAME_PLACEHOLDER, policy.csrfCookieName)
    .replaceAll(SWAGGER_CSRF_HEADER_NAME_PLACEHOLDER, policy.csrfHeaderName);

  return JSON.parse(patched) as T;
}

export function setupSwagger(
  app: INestApplication,
  configService: ConfigService,
) {
  const appEnv = configService.get<string>('APP_ENV') ?? 'development';
  const isProd = appEnv === 'production';

  const swaggerEnabled = configService.get<boolean>('SWAGGER_ENABLED') ?? false;

  const shouldEnableSwagger = swaggerEnabled && !isProd;
  if (!shouldEnableSwagger) {
    return { shouldEnableSwagger, apiBase: null as string | null };
  }

  const baseUrl = configService.get<string>(
    'BASE_URL',
    'http://localhost:3000',
  );
  const apiPrefix = configService.get<string>('API_PREFIX', 'api');
  const apiVersion = configService.get<string>('API_VERSION', '1');

  const apiBase = `${baseUrl}/${apiPrefix}/v${apiVersion}`;

  const securityPolicy = app.get(SecurityPolicyService).get();

  const runtimePolicy: SwaggerRuntimePolicy = {
    refreshCookieName: securityPolicy.auth.refreshCookieName,
    csrfCookieName: securityPolicy.csrf.cookieName,
    csrfHeaderName: securityPolicy.csrf.headerName,
  };

  const docConfig = new DocumentBuilder()
    .setTitle('MUD-State API')
    .setDescription(buildSwaggerDescription(runtimePolicy))
    .setVersion('1.0')
    .addBearerAuth(
      { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
      'access_bearer',
    )
    .addSecurity('refresh_cookie', {
      type: 'apiKey',
      in: 'cookie',
      name: runtimePolicy.refreshCookieName,
      description:
        `Signed HttpOnly refresh cookie (${runtimePolicy.refreshCookieName}) ` +
        '(set on login/register/refresh).',
    })
    .addApiKey(
      {
        type: 'apiKey',
        in: 'header',
        name: runtimePolicy.csrfHeaderName,
        description:
          `Must match ${runtimePolicy.csrfCookieName} cookie ` +
          '(double-submit CSRF).',
      },
      'csrf_header',
    )
    .addApiKey(
      {
        type: 'apiKey',
        in: 'header',
        name: 'X-CSRF-M2M-Kid',
        description: 'M2M key id (kid) for CSRF HMAC proof.',
      },
      'csrf_m2m_kid',
    )
    .addApiKey(
      {
        type: 'apiKey',
        in: 'header',
        name: 'X-CSRF-M2M-TS',
        description: 'Unix timestamp (seconds). Must be within replay window.',
      },
      'csrf_m2m_ts',
    )
    .addApiKey(
      {
        type: 'apiKey',
        in: 'header',
        name: 'X-CSRF-M2M-Nonce',
        description: 'Unique nonce (replay-protected) within replay window.',
      },
      'csrf_m2m_nonce',
    )
    .addApiKey(
      {
        type: 'apiKey',
        in: 'header',
        name: 'X-CSRF-M2M-Sign',
        description:
          'base64url(HMAC-SHA256(secret, `${kid}.${ts}.${nonce}.${METHOD}.${originalUrl}`))',
      },
      'csrf_m2m_sign',
    )
    .addSecurity('csrf_cookie', {
      type: 'apiKey',
      in: 'cookie',
      name: runtimePolicy.csrfCookieName,
      description:
        `Non-HttpOnly CSRF cookie (${runtimePolicy.csrfCookieName}) ` +
        '(15 min maxAge).',
    })
    .build();

  const rawDocument = SwaggerModule.createDocument(app, docConfig);
  const document = applySwaggerRuntimePolicy(rawDocument, runtimePolicy);

  SwaggerModule.setup(`${apiPrefix}/docs`, app, document, {
    swaggerOptions: { withCredentials: true },
  });

  return { shouldEnableSwagger, apiBase };
}
