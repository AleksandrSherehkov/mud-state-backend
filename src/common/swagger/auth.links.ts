import { applyDecorators } from '@nestjs/common';
import {
  ApiCreatedResponse,
  ApiExtraModels,
  ApiNoContentResponse,
  ApiOkResponse,
} from '@nestjs/swagger';

import { RegisterResponseDto } from 'src/auth/dto/register-response.dto';
import { TokenResponseDto } from 'src/auth/dto/token-response.dto';
import { LogoutResponseDto } from 'src/auth/dto/logout-response.dto';
import { MeResponseDto } from 'src/auth/dto/me-response.dto';
const SET_AUTH_COOKIES_HEADER = {
  'Set-Cookie': {
    description:
      'Sets authentication cookies: refreshToken (HttpOnly) and csrfToken (readable by JS). ' +
      'Exact attributes depend on env (Secure/SameSite/Path).',
    schema: { type: 'string' },

    example:
      'refreshToken=eyJ...; Path=/api; HttpOnly; SameSite=Lax; Secure; ' +
      'csrfToken=550e8400-e29b-41d4-a716-446655440000; Path=/api; SameSite=Lax; Secure',
  },
} as const;

const SET_REFRESH_COOKIE_HEADER = {
  'Set-Cookie': {
    description:
      'Sets refreshToken cookie (HttpOnly, signed). Exact attributes depend on env (Secure/SameSite/Path).',
    schema: { type: 'string' },
    example: 'refreshToken=eyJ...; Path=/api; HttpOnly; SameSite=Lax; Secure',
  },
} as const;

const SET_CSRF_COOKIE_HEADER = {
  'Set-Cookie': {
    description:
      'Sets csrfToken cookie (readable by JS, short-lived). Exact attributes depend on env (Secure/SameSite/Path).',
    schema: { type: 'string' },
    example:
      'csrfToken=550e8400-e29b-41d4-a716-446655440000; Path=/api; SameSite=Lax; Secure',
  },
} as const;

const CLEAR_AUTH_COOKIES_HEADER = {
  'Set-Cookie': {
    description:
      'Clears authentication cookies: refreshToken and csrfToken (Set-Cookie with Max-Age=0/Expires in past).',
    schema: { type: 'string' },
    example:
      'refreshToken=; Path=/api; HttpOnly; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; ' +
      'csrfToken=; Path=/api; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
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

  csrf204() {
    return applyDecorators(
      ApiNoContentResponse({
        description: 'CSRF cookie встановлено або оновлено',
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
