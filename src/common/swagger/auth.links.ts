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
