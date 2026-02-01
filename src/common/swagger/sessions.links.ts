import { applyDecorators } from '@nestjs/common';
import { ApiExtraModels, ApiOkResponse } from '@nestjs/swagger';
import { FullSessionDto } from 'src/sessions/dto/full-session.dto';
import { TerminateCountResponseDto } from 'src/sessions/dto/terminate-count-response.dto';
import { TerminateResultDto } from 'src/sessions/dto/terminate-result.dto';

export const ApiSessionsLinks = {
  mySessions200() {
    return applyDecorators(
      ApiExtraModels(FullSessionDto),
      ApiOkResponse({
        description: 'Список сессий пользователя',
        type: FullSessionDto,
        isArray: true,
        links: {
          terminateOthers: {
            operationId: 'sessions_terminateOthers',
            description: 'Далі: завершити інші сесії (requires Bearer)',
          },
          terminate: {
            operationId: 'sessions_terminate',
            description:
              'Далі: завершити конкретну сесію за IP/User-Agent (requires Bearer)',
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
            operationId: 'sessions_mySessions',
            description: 'Далі: переглянути свої сесії (requires Bearer)',
          },
        },
      }),
    );
  },

  terminate200() {
    return applyDecorators(
      ApiExtraModels(TerminateResultDto),
      ApiOkResponse({
        description: 'Результат завершення сесії',
        type: TerminateResultDto,
        links: {
          mySessions: {
            operationId: 'sessions_mySessions',
            description: 'Далі: переглянути свої сесії (requires Bearer)',
          },
        },
      }),
    );
  },

  userSessions200() {
    return applyDecorators(
      ApiExtraModels(FullSessionDto),
      ApiOkResponse({
        description: 'Список сессий указанного пользователя',
        type: FullSessionDto,
        isArray: true,
        links: {
          // можна залишити порожнім або додати переходи на users_* operationId, якщо потрібно
        },
      }),
    );
  },
};
