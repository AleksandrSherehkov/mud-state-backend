import type { INestApplication } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import type { ConfigService } from '@nestjs/config';

export function setupSwagger(
  app: INestApplication,
  configService: ConfigService,
) {
  const appEnv = configService.get<string>('APP_ENV') ?? 'development';
  const swaggerEnabled = configService.get<boolean>('SWAGGER_ENABLED') ?? true;

  const shouldEnableSwagger = swaggerEnabled && appEnv !== 'production';
  if (!shouldEnableSwagger)
    return { shouldEnableSwagger, apiBase: null as string | null };

  const baseUrl = configService.get<string>(
    'BASE_URL',
    'http://localhost:3000',
  );
  const apiPrefix = configService.get<string>('API_PREFIX', 'api');
  const apiVersion = configService.get<string>('API_VERSION', '1');

  const apiBase = `${baseUrl}/${apiPrefix}/v${apiVersion}`;

  const docConfig = new DocumentBuilder()
    .setTitle('MUD-State API')
    .setDescription(
      [
        'API for the MUD simulation state backend.',
        '',
        'Auth model:',
        '- Access token: Bearer JWT in Authorization header.',
        '- Refresh token: stored in cookie `refreshToken` (HttpOnly, signed).',
        '- CSRF: double-submit token stored in cookie `csrfToken` (non-HttpOnly) + header `X-CSRF-Token`.',
        '',
        'CSRF rotation:',
        '- `GET /auth/csrf` sets/renews `csrfToken` cookie (short-lived).',
        '- `POST /auth/refresh` rotates BOTH `refreshToken` and `csrfToken` cookies.',
        '',
        'Notes:',
        '- Cookies require CORS credentials and proper SameSite/Secure settings.',
        '- `csrfToken` cookie maxAge is 15 minutes.',
      ].join('\n'),
    )
    .setVersion('1.0')
    .addBearerAuth(
      { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
      'access_bearer',
    )
    .addSecurity('refresh_cookie', {
      type: 'apiKey',
      in: 'cookie',
      name: 'refreshToken',
      description:
        'Signed HttpOnly refresh cookie (set on login/register/refresh).',
    })
    .addApiKey(
      {
        type: 'apiKey',
        in: 'header',
        name: 'X-CSRF-Token',
        description: 'Must match csrfToken cookie (double-submit CSRF).',
      },
      'csrf_header',
    )

    .addSecurity('csrf_cookie', {
      type: 'apiKey',
      in: 'cookie',
      name: 'csrfToken',
      description: 'Non-HttpOnly CSRF cookie (15 min maxAge).',
    })
    .addServer(apiBase, 'API base')
    .build();

  const document = SwaggerModule.createDocument(app, docConfig);
  SwaggerModule.setup(`${apiPrefix}/docs`, app, document);

  return { shouldEnableSwagger, apiBase };
}
