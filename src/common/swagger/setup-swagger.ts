import type { INestApplication } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import type { ConfigService } from '@nestjs/config';

export function setupSwagger(
  app: INestApplication,
  configService: ConfigService,
) {
  const appEnv = configService.get<string>('APP_ENV') ?? 'development';
  const isProd = appEnv === 'production';

  const swaggerEnabled = configService.get<boolean>('SWAGGER_ENABLED') ?? false;

  const shouldEnableSwagger = swaggerEnabled && !isProd;
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
        'API для бекенду стану симуляції MUD.',
        '',
        'Модель автентифікації:',
        '- Access token: Bearer JWT у заголовку `Authorization`.',
        '- Refresh token: зберігається у cookie `refreshToken` (HttpOnly, signed).',
        '',
        'CSRF-захист (double-submit):',
        '- Cookie `csrfToken` (не HttpOnly, короткоживуча) + заголовок `X-CSRF-Token`.',
        '- Обовʼязковий для ВСІХ ендпоінтів, які встановлюють / оновлюють / очищають auth cookies:',
        '  - POST /auth/register',
        '  - POST /auth/login',
        '  - POST /auth/refresh',
        '  - POST /auth/logout',
        '',
        'Ініціалізація CSRF cookie:',
        '- GET /auth/csrf встановлює або оновлює cookie `csrfToken` (15 хвилин).',
        '',
        'Ротація токенів:',
        '- POST /auth/refresh виконує ротацію ОБОХ cookies: `refreshToken` та `csrfToken`.',
        '',
        'Примітки:',
        '- Cookies потребують `credentials: true` у CORS та коректних налаштувань `SameSite` / `Secure`.',
        '- У production режимі `SameSite=None` вимагає `Secure=true` (HTTPS).',
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
    .build();

  const document = SwaggerModule.createDocument(app, docConfig);
  SwaggerModule.setup(`${apiPrefix}/docs`, app, document, {
    swaggerOptions: { withCredentials: true },
  });

  return { shouldEnableSwagger, apiBase };
}
