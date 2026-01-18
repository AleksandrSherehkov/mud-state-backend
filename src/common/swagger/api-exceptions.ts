import { applyDecorators } from '@nestjs/common';
import {
  ApiBadRequestResponse,
  ApiUnauthorizedResponse,
  ApiForbiddenResponse,
  ApiNotFoundResponse,
  ApiConflictResponse,
  ApiInternalServerErrorResponse,
  ApiTooManyRequestsResponse,
} from '@nestjs/swagger';

type CommonErrorsOptions = {
  includeBadRequest?: boolean;
  includeUnauthorized?: boolean;
  includeForbidden?: boolean;
  includeTooManyRequests?: boolean;
  includeInternal?: boolean;

  badRequestDescription?: string;
  badRequestMessageExample?: string | string[];

  unauthorizedDescription?: string;
  unauthorizedMessageExample?: string | string[];

  forbiddenDescription?: string;
  forbiddenMessageExample?: string | string[];

  tooManyRequestsDescription?: string;
  tooManyRequestsMessageExample?: string | string[];

  internalDescription?: string;
  internalMessageExample?: string | string[];
};

type MutationErrorsOptions = CommonErrorsOptions & {
  includeConflict?: boolean;
  notFoundMessage?: string;

  conflictDescription?: string;
  conflictMessageExample?: string | string[];
};

type QueryErrorsOptions = CommonErrorsOptions & {
  notFoundMessage?: string;
};

function makeErrorExample(
  statusCode: number,
  message: string | string[],
  error: string,
) {
  return { statusCode, message, error };
}

export function ApiMutationErrorResponses(options?: MutationErrorsOptions) {
  const includeBadRequest = options?.includeBadRequest ?? true;
  const includeUnauthorized = options?.includeUnauthorized ?? true;
  const includeForbidden = options?.includeForbidden ?? true;
  const includeTooManyRequests = options?.includeTooManyRequests ?? true;
  const includeInternal = options?.includeInternal ?? true;

  const includeConflict = options?.includeConflict ?? true;
  const notFoundMessage = options?.notFoundMessage;

  const badRequestDescription =
    options?.badRequestDescription ?? 'Некоректні вхідні дані';
  const badRequestMessageExample =
    options?.badRequestMessageExample ??
    (['email має бути валідним', 'password обов’язковий'] as string[]);

  const unauthorizedDescription =
    options?.unauthorizedDescription ?? 'Неавторизований доступ';
  const unauthorizedMessageExample =
    options?.unauthorizedMessageExample ?? 'Необхідна авторизація';

  const forbiddenDescription =
    options?.forbiddenDescription ?? 'Доступ заборонено';
  const forbiddenMessageExample =
    options?.forbiddenMessageExample ?? 'У вас немає прав для цієї дії';

  const conflictDescription =
    options?.conflictDescription ??
    'Конфлікт ресурсу (наприклад, email вже існує)';
  const conflictMessageExample =
    options?.conflictMessageExample ?? 'Email вже використовується';

  const tooManyRequestsDescription =
    options?.tooManyRequestsDescription ??
    'Занадто багато запитів (rate limit)';
  const tooManyRequestsMessageExample =
    options?.tooManyRequestsMessageExample ?? 'Too Many Requests';

  const internalDescription =
    options?.internalDescription ?? 'Внутрішня помилка сервера';
  const internalMessageExample =
    options?.internalMessageExample ?? 'Щось пішло не так на сервері';

  const decorators = [
    ...(includeBadRequest
      ? [
          ApiBadRequestResponse({
            description: badRequestDescription,
            schema: {
              example: makeErrorExample(
                400,
                badRequestMessageExample,
                'Bad Request',
              ),
            },
          }),
        ]
      : []),

    ...(includeUnauthorized
      ? [
          ApiUnauthorizedResponse({
            description: unauthorizedDescription,
            schema: {
              example: makeErrorExample(
                401,
                unauthorizedMessageExample,
                'Unauthorized',
              ),
            },
          }),
        ]
      : []),

    ...(includeForbidden
      ? [
          ApiForbiddenResponse({
            description: forbiddenDescription,
            schema: {
              example: makeErrorExample(
                403,
                forbiddenMessageExample,
                'Forbidden',
              ),
            },
          }),
        ]
      : []),

    ...(notFoundMessage
      ? [
          ApiNotFoundResponse({
            description: notFoundMessage,
            schema: {
              example: makeErrorExample(404, notFoundMessage, 'Not Found'),
            },
          }),
        ]
      : []),

    ...(includeConflict
      ? [
          ApiConflictResponse({
            description: conflictDescription,
            schema: {
              example: makeErrorExample(
                409,
                conflictMessageExample,
                'Conflict',
              ),
            },
          }),
        ]
      : []),

    ...(includeTooManyRequests
      ? [
          ApiTooManyRequestsResponse({
            description: tooManyRequestsDescription,
            schema: {
              example: makeErrorExample(
                429,
                tooManyRequestsMessageExample,
                'Too Many Requests',
              ),
            },
          }),
        ]
      : []),

    ...(includeInternal
      ? [
          ApiInternalServerErrorResponse({
            description: internalDescription,
            schema: {
              example: makeErrorExample(
                500,
                internalMessageExample,
                'Internal Server Error',
              ),
            },
          }),
        ]
      : []),
  ];

  return applyDecorators(...decorators);
}

export function ApiQueryErrorResponses(
  notFoundOrOptions: string | QueryErrorsOptions = 'Ресурс не знайдено',
) {
  const opts: QueryErrorsOptions =
    typeof notFoundOrOptions === 'string'
      ? { notFoundMessage: notFoundOrOptions }
      : notFoundOrOptions;

  const includeBadRequest = opts.includeBadRequest ?? true;
  const includeUnauthorized = opts.includeUnauthorized ?? true;
  const includeForbidden = opts.includeForbidden ?? true;
  const includeTooManyRequests = opts.includeTooManyRequests ?? true;
  const includeInternal = opts.includeInternal ?? true;

  const notFoundMessage = opts.notFoundMessage ?? 'Ресурс не знайдено';

  const badRequestDescription =
    opts.badRequestDescription ?? 'Некоректні query-параметри';
  const badRequestMessageExample =
    opts.badRequestMessageExample ??
    (['email має бути валідним', 'email не повинен бути порожнім'] as string[]);

  const unauthorizedDescription =
    opts.unauthorizedDescription ?? 'Неавторизований доступ';
  const unauthorizedMessageExample =
    opts.unauthorizedMessageExample ?? 'Необхідна авторизація';

  const forbiddenDescription = opts.forbiddenDescription ?? 'Доступ заборонено';
  const forbiddenMessageExample =
    opts.forbiddenMessageExample ?? 'У вас немає прав для цієї дії';

  const tooManyRequestsDescription =
    opts.tooManyRequestsDescription ?? 'Занадто багато запитів (rate limit)';
  const tooManyRequestsMessageExample =
    opts.tooManyRequestsMessageExample ?? 'Too Many Requests';

  const internalDescription =
    opts.internalDescription ?? 'Внутрішня помилка сервера';
  const internalMessageExample =
    opts.internalMessageExample ?? 'Щось пішло не так на сервері';

  const decorators = [
    ...(includeBadRequest
      ? [
          ApiBadRequestResponse({
            description: badRequestDescription,
            schema: {
              example: makeErrorExample(
                400,
                badRequestMessageExample,
                'Bad Request',
              ),
            },
          }),
        ]
      : []),

    ...(includeUnauthorized
      ? [
          ApiUnauthorizedResponse({
            description: unauthorizedDescription,
            schema: {
              example: makeErrorExample(
                401,
                unauthorizedMessageExample,
                'Unauthorized',
              ),
            },
          }),
        ]
      : []),

    ...(includeForbidden
      ? [
          ApiForbiddenResponse({
            description: forbiddenDescription,
            schema: {
              example: makeErrorExample(
                403,
                forbiddenMessageExample,
                'Forbidden',
              ),
            },
          }),
        ]
      : []),

    ApiNotFoundResponse({
      description: notFoundMessage,
      schema: {
        example: makeErrorExample(404, notFoundMessage, 'Not Found'),
      },
    }),

    ...(includeTooManyRequests
      ? [
          ApiTooManyRequestsResponse({
            description: tooManyRequestsDescription,
            schema: {
              example: makeErrorExample(
                429,
                tooManyRequestsMessageExample,
                'Too Many Requests',
              ),
            },
          }),
        ]
      : []),

    ...(includeInternal
      ? [
          ApiInternalServerErrorResponse({
            description: internalDescription,
            schema: {
              example: makeErrorExample(
                500,
                internalMessageExample,
                'Internal Server Error',
              ),
            },
          }),
        ]
      : []),
  ];

  return applyDecorators(...decorators);
}

export function ApiListErrorResponses(options?: QueryErrorsOptions) {
  const includeBadRequest = options?.includeBadRequest ?? true;
  const includeUnauthorized = options?.includeUnauthorized ?? true;
  const includeForbidden = options?.includeForbidden ?? true;
  const includeTooManyRequests = options?.includeTooManyRequests ?? true;
  const includeInternal = options?.includeInternal ?? true;

  const badRequestDescription =
    options?.badRequestDescription ?? 'Некоректні query-параметри';
  const badRequestMessageExample =
    options?.badRequestMessageExample ??
    ([
      'limit має бути числом',
      'limit повинен бути в діапазоні 1..100',
    ] as string[]);

  const unauthorizedDescription =
    options?.unauthorizedDescription ?? 'Неавторизований доступ';
  const unauthorizedMessageExample =
    options?.unauthorizedMessageExample ?? 'Необхідна авторизація';

  const forbiddenDescription =
    options?.forbiddenDescription ?? 'Доступ заборонено';
  const forbiddenMessageExample =
    options?.forbiddenMessageExample ?? 'У вас немає прав для цієї дії';

  const tooManyRequestsDescription =
    options?.tooManyRequestsDescription ??
    'Занадто багато запитів (rate limit)';
  const tooManyRequestsMessageExample =
    options?.tooManyRequestsMessageExample ?? 'Too Many Requests';

  const internalDescription =
    options?.internalDescription ?? 'Внутрішня помилка сервера';
  const internalMessageExample =
    options?.internalMessageExample ?? 'Щось пішло не так на сервері';

  const decorators = [
    ...(includeBadRequest
      ? [
          ApiBadRequestResponse({
            description: badRequestDescription,
            schema: {
              example: makeErrorExample(
                400,
                badRequestMessageExample,
                'Bad Request',
              ),
            },
          }),
        ]
      : []),

    ...(includeUnauthorized
      ? [
          ApiUnauthorizedResponse({
            description: unauthorizedDescription,
            schema: {
              example: makeErrorExample(
                401,
                unauthorizedMessageExample,
                'Unauthorized',
              ),
            },
          }),
        ]
      : []),

    ...(includeForbidden
      ? [
          ApiForbiddenResponse({
            description: forbiddenDescription,
            schema: {
              example: makeErrorExample(
                403,
                forbiddenMessageExample,
                'Forbidden',
              ),
            },
          }),
        ]
      : []),

    ...(includeTooManyRequests
      ? [
          ApiTooManyRequestsResponse({
            description: tooManyRequestsDescription,
            schema: {
              example: makeErrorExample(
                429,
                tooManyRequestsMessageExample,
                'Too Many Requests',
              ),
            },
          }),
        ]
      : []),

    ...(includeInternal
      ? [
          ApiInternalServerErrorResponse({
            description: internalDescription,
            schema: {
              example: makeErrorExample(
                500,
                internalMessageExample,
                'Internal Server Error',
              ),
            },
          }),
        ]
      : []),
  ];

  return applyDecorators(...decorators);
}
