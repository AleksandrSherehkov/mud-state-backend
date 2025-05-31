import { applyDecorators } from '@nestjs/common';
import {
  ApiBadRequestResponse,
  ApiUnauthorizedResponse,
  ApiForbiddenResponse,
  ApiNotFoundResponse,
  ApiConflictResponse,
  ApiInternalServerErrorResponse,
} from '@nestjs/swagger';

export function ApiMutationErrorResponses() {
  return applyDecorators(
    ApiBadRequestResponse({
      description: 'Некоректні вхідні дані',
      schema: {
        example: {
          statusCode: 400,
          message: ['email має бути валідним', 'password обов’язковий'],
          error: 'Bad Request',
        },
      },
    }),
    ApiUnauthorizedResponse({
      description: 'Неавторизований доступ',
      schema: {
        example: {
          statusCode: 401,
          message: 'Необхідна авторизація',
          error: 'Unauthorized',
        },
      },
    }),
    ApiForbiddenResponse({
      description: 'Доступ заборонено',
      schema: {
        example: {
          statusCode: 403,
          message: 'У вас немає прав для цієї дії',
          error: 'Forbidden',
        },
      },
    }),
    ApiConflictResponse({
      description: 'Конфлікт ресурсу (наприклад, email вже існує)',
      schema: {
        example: {
          statusCode: 409,
          message: 'Email вже використовується',
          error: 'Conflict',
        },
      },
    }),
    ApiInternalServerErrorResponse({
      description: 'Внутрішня помилка сервера',
      schema: {
        example: {
          statusCode: 500,
          message: 'Щось пішло не так на сервері',
          error: 'Internal Server Error',
        },
      },
    }),
  );
}

export function ApiQueryErrorResponses(notFoundMessage = 'Ресурс не знайдено') {
  return applyDecorators(
    ApiUnauthorizedResponse({
      description: 'Неавторизований доступ',
      schema: {
        example: {
          statusCode: 401,
          message: 'Необхідна авторизація',
          error: 'Unauthorized',
        },
      },
    }),
    ApiForbiddenResponse({
      description: 'Доступ заборонено',
      schema: {
        example: {
          statusCode: 403,
          message: 'У вас немає прав для цієї дії',
          error: 'Forbidden',
        },
      },
    }),
    ApiNotFoundResponse({
      description: notFoundMessage,
      schema: {
        example: {
          statusCode: 404,
          message: notFoundMessage,
          error: 'Not Found',
        },
      },
    }),
    ApiInternalServerErrorResponse({
      description: 'Внутрішня помилка сервера',
      schema: {
        example: {
          statusCode: 500,
          message: 'Щось пішло не так на сервері',
          error: 'Internal Server Error',
        },
      },
    }),
  );
}
