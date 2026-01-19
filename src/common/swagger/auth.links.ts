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
import { FullSessionDto } from 'src/auth/dto/full-session.dto';
import { ActiveSessionDto } from 'src/auth/dto/active-session.dto';
import { RefreshTokenSessionDto } from 'src/auth/dto/refresh-token-session.dto';
import { TerminateCountResponseDto } from 'src/auth/dto/terminate-count-response.dto';
import { TerminateResultDto } from 'src/auth/dto/terminate-result.dto';

export const ApiAuthLinks = {
  register201() {
    return applyDecorators(
      ApiExtraModels(
        RegisterResponseDto,
        MeResponseDto,
        FullSessionDto,
        ActiveSessionDto,
      ),
      ApiCreatedResponse({
        description: 'Користувач створений',
        type: RegisterResponseDto,
        links: {
          me: {
            operationId: 'auth_me',
            description: 'Далі: отримати свій профіль (requires Bearer)',
          },
          mySessions: {
            operationId: 'auth_sessions_me',
            description: 'Далі: переглянути свої сесії (requires Bearer)',
          },
          activeSessions: {
            operationId: 'auth_sessions_active',
            description:
              'Далі: активні сесії (requires Bearer, ADMIN/MODERATOR)',
          },
        },
      }),
    );
  },

  login200() {
    return applyDecorators(
      ApiExtraModels(TokenResponseDto, MeResponseDto, FullSessionDto),
      ApiOkResponse({
        description: 'Успішний логін',
        type: TokenResponseDto,
        links: {
          me: {
            operationId: 'auth_me',
            description: 'Далі: отримати свій профіль (requires Bearer)',
          },
          mySessions: {
            operationId: 'auth_sessions_me',
            description: 'Далі: переглянути свої сесії (requires Bearer)',
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
      ApiExtraModels(TokenResponseDto, MeResponseDto),
      ApiOkResponse({
        description: 'Нові токени',
        type: TokenResponseDto,
        links: {
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
      ApiExtraModels(LogoutResponseDto, TokenResponseDto),
      ApiOkResponse({
        description: 'Користувач вийшов',
        type: LogoutResponseDto,
        links: {
          login: {
            operationId: 'auth_login',
            description: 'Далі: login знову',
          },
          register: {
            operationId: 'auth_register',
            description: 'Або: створити нового користувача',
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
          mySessions: {
            operationId: 'auth_sessions_me',
            description:
              'Далі: переглянути сесії поточного користувача (ADMIN/MODERATOR)',
          },
          logout: {
            operationId: 'auth_logout',
            description: 'Далі: logout',
          },
        },
      }),
    );
  },

  userSessions200() {
    return applyDecorators(
      ApiExtraModels(RefreshTokenSessionDto),
      ApiOkResponse({
        description: 'Активні токени',
        type: [RefreshTokenSessionDto],
        links: {
          activeSessions: {
            operationId: 'auth_sessions_active',
            description: 'Далі: активні сесії (ADMIN/MODERATOR)',
          },
          mySessions: {
            operationId: 'auth_sessions_me',
            description: 'Далі: мої сесії (ADMIN/MODERATOR)',
          },
        },
      }),
    );
  },

  activeSessions200() {
    return applyDecorators(
      ApiExtraModels(ActiveSessionDto),
      ApiOkResponse({
        description: 'Список активних сесій з IP, User-Agent і часом старту',
        type: [ActiveSessionDto],
        links: {
          mySessions: {
            operationId: 'auth_sessions_me',
            description: 'Далі: мої сесії (ADMIN/MODERATOR)',
          },
          terminateOthers: {
            operationId: 'auth_sessions_terminate_others',
            description: 'Далі: завершити всі інші сесії',
          },
        },
      }),
    );
  },

  mySessions200() {
    return applyDecorators(
      ApiExtraModels(FullSessionDto),
      ApiOkResponse({
        description: 'Усі сесії поточного користувача',
        type: [FullSessionDto],
        links: {
          terminateOthers: {
            operationId: 'auth_sessions_terminate_others',
            description: 'Далі: завершити всі інші сесії',
          },
          terminateSpecific: {
            operationId: 'auth_sessions_terminate',
            description: 'Далі: завершити конкретну сесію',
          },
        },
      }),
    );
  },

  terminateOthers200() {
    return applyDecorators(
      ApiExtraModels(TerminateCountResponseDto),
      ApiOkResponse({
        description: 'Інші сесії завершено',
        type: TerminateCountResponseDto,
        links: {
          mySessions: {
            operationId: 'auth_sessions_me',
            description: 'Далі: перевірити свої сесії',
          },
        },
      }),
    );
  },

  terminateSpecific200() {
    return applyDecorators(
      ApiExtraModels(TerminateResultDto),
      ApiOkResponse({
        description: 'Сесію завершено',
        type: TerminateResultDto,
        links: {
          mySessions: {
            operationId: 'auth_sessions_me',
            description: 'Далі: перевірити свої сесії',
          },
        },
      }),
    );
  },
} as const;
