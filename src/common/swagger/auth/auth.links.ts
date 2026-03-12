import { applyDecorators } from '@nestjs/common';
import {
  ApiCreatedResponse,
  ApiExtraModels,
  ApiOkResponse,
} from '@nestjs/swagger';

import { RegisterResponseDto } from 'src/auth/dto/register-response.dto';
import { TokenResponseDto } from 'src/auth/dto/token-response.dto';
import { LogoutResponseDto } from 'src/auth/dto/logout-response.dto';
import { MeResponseDto } from 'src/auth/dto/me-response.dto';
import { CsrfResponseDto } from 'src/auth/dto/csrf-response.dto';
import {
  SWAGGER_CSRF_COOKIE_NAME_PLACEHOLDER,
  SWAGGER_CSRF_HEADER_NAME_PLACEHOLDER,
  SWAGGER_REFRESH_COOKIE_NAME_PLACEHOLDER,
} from './auth.placeholders';

const SET_AUTH_COOKIES_HEADER = {
  'Set-Cookie': {
    description:
      `Sets authentication cookies: ${SWAGGER_REFRESH_COOKIE_NAME_PLACEHOLDER} (HttpOnly, signed) and ` +
      `${SWAGGER_CSRF_COOKIE_NAME_PLACEHOLDER} (signed, readable by JS). ` +
      `Client must use ${SWAGGER_CSRF_COOKIE_NAME_PLACEHOLDER} from JSON body for ` +
      `${SWAGGER_CSRF_HEADER_NAME_PLACEHOLDER} header (do not read from cookie). ` +
      'Exact attributes depend on env (Secure/SameSite/Path).',
    schema: { type: 'string' },
    example:
      `${SWAGGER_REFRESH_COOKIE_NAME_PLACEHOLDER}=s%3AeyJ...<sig>; Path=/api; HttpOnly; SameSite=Lax; Secure; ` +
      `${SWAGGER_CSRF_COOKIE_NAME_PLACEHOLDER}=s%3A550e8400-e29b-41d4-a716-446655440000.<sig>; Path=/api; SameSite=Lax; Secure`,
  },
} as const;

const SET_REFRESH_COOKIE_HEADER = {
  'Set-Cookie': {
    description:
      `Sets ${SWAGGER_REFRESH_COOKIE_NAME_PLACEHOLDER} cookie (HttpOnly, signed). ` +
      'Exact attributes depend on env (Secure/SameSite/Path).',
    schema: { type: 'string' },
    example: `${SWAGGER_REFRESH_COOKIE_NAME_PLACEHOLDER}=s%3AeyJ...<sig>; Path=/api; HttpOnly; SameSite=Lax; Secure`,
  },
} as const;

const SET_CSRF_COOKIE_HEADER = {
  'Set-Cookie': {
    description:
      `Sets ${SWAGGER_CSRF_COOKIE_NAME_PLACEHOLDER} cookie (signed, short-lived). ` +
      `Client should use ${SWAGGER_CSRF_COOKIE_NAME_PLACEHOLDER} from response body for ` +
      `${SWAGGER_CSRF_HEADER_NAME_PLACEHOLDER} header. ` +
      'Exact attributes depend on env (Secure/SameSite/Path).',
    schema: { type: 'string' },
    example: `${SWAGGER_CSRF_COOKIE_NAME_PLACEHOLDER}=s%3A550e8400-e29b-41d4-a716-446655440000.<sig>; Path=/api; SameSite=Lax; Secure`,
  },
} as const;

const CLEAR_AUTH_COOKIES_HEADER = {
  'Set-Cookie': {
    description:
      `Clears authentication cookies: ${SWAGGER_REFRESH_COOKIE_NAME_PLACEHOLDER} and ` +
      `${SWAGGER_CSRF_COOKIE_NAME_PLACEHOLDER} ` +
      '(Set-Cookie with Max-Age=0/Expires in past).',
    schema: { type: 'string' },
    example:
      `${SWAGGER_REFRESH_COOKIE_NAME_PLACEHOLDER}=; Path=/api; HttpOnly; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; ` +
      `${SWAGGER_CSRF_COOKIE_NAME_PLACEHOLDER}=; Path=/api; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`,
  },
} as const;

export const ApiAuthLinks = {
  register201() {
    return applyDecorators(
      ApiExtraModels(RegisterResponseDto),
      ApiCreatedResponse({
        description: 'Користувач створений',
        type: RegisterResponseDto,
        links: {
          login: {
            operationId: 'auth_login',
            description: 'Далі: виконати login (PUBLIC)',
          },
          me: {
            operationId: 'auth_me',
            description: 'Далі: отримати свій профіль (requires Bearer)',
          },
          logout: {
            operationId: 'auth_logout',
            description: 'Далі: logout (requires Bearer)',
          },
        },
        headers: SET_AUTH_COOKIES_HEADER,
      }),
    );
  },

  login200() {
    return applyDecorators(
      ApiExtraModels(TokenResponseDto),
      ApiOkResponse({
        description: 'Успішний логін',
        type: TokenResponseDto,
        links: {
          refresh: {
            operationId: 'auth_refresh',
            description: 'Далі: оновити токени (PUBLIC)',
          },
          me: {
            operationId: 'auth_me',
            description: 'Далі: отримати свій профіль (requires Bearer)',
          },
          logout: {
            operationId: 'auth_logout',
            description: 'Далі: logout (requires Bearer)',
          },
        },
        headers: SET_AUTH_COOKIES_HEADER,
      }),
    );
  },

  csrf200() {
    return applyDecorators(
      ApiExtraModels(CsrfResponseDto),
      ApiOkResponse({
        description: `CSRF cookie встановлено/оновлено + повернуто ${SWAGGER_CSRF_COOKIE_NAME_PLACEHOLDER} для заголовка ${SWAGGER_CSRF_HEADER_NAME_PLACEHOLDER}`,
        type: CsrfResponseDto,
        headers: SET_CSRF_COOKIE_HEADER,
        links: {
          register: {
            operationId: 'auth_register',
            description: 'Далі: реєстрація (PUBLIC)',
          },
          login: {
            operationId: 'auth_login',
            description: 'Далі: login (PUBLIC)',
          },
        },
      }),
    );
  },

  refresh200() {
    return applyDecorators(
      ApiExtraModels(TokenResponseDto),
      ApiOkResponse({
        description: 'Нові токени',
        type: TokenResponseDto,
        links: {
          refresh: {
            operationId: 'auth_refresh',
            description: 'Далі: повторне оновлення токенів (PUBLIC)',
          },
          me: {
            operationId: 'auth_me',
            description: 'Далі: отримати свій профіль (requires Bearer)',
          },
          logout: {
            operationId: 'auth_logout',
            description: 'Далі: logout (requires Bearer)',
          },
        },
        headers: SET_REFRESH_COOKIE_HEADER,
      }),
    );
  },

  logout200() {
    return applyDecorators(
      ApiExtraModels(LogoutResponseDto),
      ApiOkResponse({
        description: 'Успішний вихід',
        type: LogoutResponseDto,
        links: {
          login: {
            operationId: 'auth_login',
            description: 'Далі: login (PUBLIC)',
          },
          register: {
            operationId: 'auth_register',
            description: 'Далі: register (PUBLIC)',
          },
        },
        headers: CLEAR_AUTH_COOKIES_HEADER,
      }),
    );
  },

  me200() {
    return applyDecorators(
      ApiExtraModels(MeResponseDto),
      ApiOkResponse({
        description: 'Профіль користувача',
        type: MeResponseDto,
        links: {
          logout: {
            operationId: 'auth_logout',
            description: 'Далі: logout (requires Bearer)',
          },
        },
      }),
    );
  },
};
