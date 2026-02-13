import { applyDecorators } from '@nestjs/common';
import {
  ApiBadRequestResponse,
  ApiUnauthorizedResponse,
  ApiForbiddenResponse,
  ApiNotFoundResponse,
  ApiConflictResponse,
  ApiInternalServerErrorResponse,
  ApiTooManyRequestsResponse,
  ApiExtraModels,
  getSchemaPath,
} from '@nestjs/swagger';
import { ApiErrorResponseDto } from '../dto/api-error-response.dto';

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
type ApiErrorExampleValue = {
  statusCode: number;
  message: string | string[];
  error: string;
  timestamp: string;
  path: string;
  requestId?: string;
};

function makeErrorExample(
  statusCode: number,
  message: string | string[],
  error: string,
  path = '/api/v1/example',
) {
  return {
    statusCode,
    message,
    error,
    timestamp: '2026-02-02T00:00:00.000Z',
    path,
    requestId: 'req_01J2ABCDEF...',
  };
}

function jsonErrorContent(exampleValue: ApiErrorExampleValue) {
  return {
    'application/json': {
      schema: { $ref: getSchemaPath(ApiErrorResponseDto) },
      examples: { default: { value: exampleValue } },
    },
  };
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
    (['Некоректні вхідні дані'] as string[]);

  const unauthorizedDescription =
    options?.unauthorizedDescription ?? 'Неавторизований доступ';
  const unauthorizedMessageExample =
    options?.unauthorizedMessageExample ?? 'Unauthorized';

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
    options?.tooManyRequestsMessageExample ??
    'ThrottlerException: Too Many Requests';

  const internalDescription =
    options?.internalDescription ?? 'Внутрішня помилка сервера';
  const internalMessageExample =
    options?.internalMessageExample ?? 'Internal server error';

  const decorators = [
    ApiExtraModels(ApiErrorResponseDto),

    ...(includeBadRequest
      ? [
          ApiBadRequestResponse({
            description: badRequestDescription,
            content: jsonErrorContent(
              makeErrorExample(
                400,
                badRequestMessageExample,
                'Bad Request',
                '/api/v1/example',
              ),
            ),
          }),
        ]
      : []),

    ...(includeUnauthorized
      ? [
          ApiUnauthorizedResponse({
            description: unauthorizedDescription,
            content: jsonErrorContent(
              makeErrorExample(
                401,
                unauthorizedMessageExample,
                'Unauthorized',
                '/api/v1/example',
              ),
            ),
          }),
        ]
      : []),

    ...(includeForbidden
      ? [
          ApiForbiddenResponse({
            description: forbiddenDescription,
            content: jsonErrorContent(
              makeErrorExample(
                403,
                forbiddenMessageExample,
                'Forbidden',
                '/api/v1/example',
              ),
            ),
          }),
        ]
      : []),

    ...(notFoundMessage
      ? [
          ApiNotFoundResponse({
            description: notFoundMessage,
            content: jsonErrorContent(
              makeErrorExample(
                404,
                notFoundMessage,
                'Not Found',
                '/api/v1/example',
              ),
            ),
          }),
        ]
      : []),

    ...(includeConflict
      ? [
          ApiConflictResponse({
            description: conflictDescription,
            content: jsonErrorContent(
              makeErrorExample(
                409,
                conflictMessageExample,
                'Conflict',
                '/api/v1/example',
              ),
            ),
          }),
        ]
      : []),

    ...(includeTooManyRequests
      ? [
          ApiTooManyRequestsResponse({
            description: tooManyRequestsDescription,
            content: jsonErrorContent(
              makeErrorExample(
                429,
                tooManyRequestsMessageExample,
                'Too Many Requests',
                '/api/v1/example',
              ),
            ),
          }),
        ]
      : []),

    ...(includeInternal
      ? [
          ApiInternalServerErrorResponse({
            description: internalDescription,
            content: jsonErrorContent(
              makeErrorExample(
                500,
                internalMessageExample,
                'Internal Server Error',
                '/api/v1/example',
              ),
            ),
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
    opts.unauthorizedMessageExample ?? 'Unauthorized';

  const forbiddenDescription = opts.forbiddenDescription ?? 'Доступ заборонено';
  const forbiddenMessageExample =
    opts.forbiddenMessageExample ?? 'У вас немає прав для цієї дії';

  const tooManyRequestsDescription =
    opts.tooManyRequestsDescription ?? 'Занадто багато запитів (rate limit)';
  const tooManyRequestsMessageExample =
    opts.tooManyRequestsMessageExample ??
    'ThrottlerException: Too Many Requests';

  const internalDescription =
    opts.internalDescription ?? 'Внутрішня помилка сервера';
  const internalMessageExample =
    opts.internalMessageExample ?? 'Internal server error';

  const decorators = [
    ApiExtraModels(ApiErrorResponseDto),

    ...(includeBadRequest
      ? [
          ApiBadRequestResponse({
            description: badRequestDescription,
            content: jsonErrorContent(
              makeErrorExample(
                400,
                badRequestMessageExample,
                'Bad Request',
                '/api/v1/example',
              ),
            ),
          }),
        ]
      : []),

    ...(includeUnauthorized
      ? [
          ApiUnauthorizedResponse({
            description: unauthorizedDescription,
            content: jsonErrorContent(
              makeErrorExample(
                401,
                unauthorizedMessageExample,
                'Unauthorized',
                '/api/v1/example',
              ),
            ),
          }),
        ]
      : []),

    ...(includeForbidden
      ? [
          ApiForbiddenResponse({
            description: forbiddenDescription,
            content: jsonErrorContent(
              makeErrorExample(
                403,
                forbiddenMessageExample,
                'Forbidden',
                '/api/v1/example',
              ),
            ),
          }),
        ]
      : []),

    ApiNotFoundResponse({
      description: notFoundMessage,
      content: jsonErrorContent(
        makeErrorExample(404, notFoundMessage, 'Not Found', '/api/v1/example'),
      ),
    }),

    ...(includeTooManyRequests
      ? [
          ApiTooManyRequestsResponse({
            description: tooManyRequestsDescription,
            content: jsonErrorContent(
              makeErrorExample(
                429,
                tooManyRequestsMessageExample,
                'Too Many Requests',
                '/api/v1/example',
              ),
            ),
          }),
        ]
      : []),

    ...(includeInternal
      ? [
          ApiInternalServerErrorResponse({
            description: internalDescription,
            content: jsonErrorContent(
              makeErrorExample(
                500,
                internalMessageExample,
                'Internal Server Error',
                '/api/v1/example',
              ),
            ),
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
    options?.unauthorizedMessageExample ?? 'Unauthorized';

  const forbiddenDescription =
    options?.forbiddenDescription ?? 'Доступ заборонено';
  const forbiddenMessageExample =
    options?.forbiddenMessageExample ?? 'У вас немає прав для цієї дії';

  const tooManyRequestsDescription =
    options?.tooManyRequestsDescription ??
    'Занадто багато запитів (rate limit)';
  const tooManyRequestsMessageExample =
    options?.tooManyRequestsMessageExample ??
    'ThrottlerException: Too Many Requests';

  const internalDescription =
    options?.internalDescription ?? 'Внутрішня помилка сервера';
  const internalMessageExample =
    options?.internalMessageExample ?? 'Internal server error';

  const decorators = [
    ApiExtraModels(ApiErrorResponseDto),

    ...(includeBadRequest
      ? [
          ApiBadRequestResponse({
            description: badRequestDescription,
            content: jsonErrorContent(
              makeErrorExample(
                400,
                badRequestMessageExample,
                'Bad Request',
                '/api/v1/example',
              ),
            ),
          }),
        ]
      : []),

    ...(includeUnauthorized
      ? [
          ApiUnauthorizedResponse({
            description: unauthorizedDescription,
            content: jsonErrorContent(
              makeErrorExample(
                401,
                unauthorizedMessageExample,
                'Unauthorized',
                '/api/v1/example',
              ),
            ),
          }),
        ]
      : []),

    ...(includeForbidden
      ? [
          ApiForbiddenResponse({
            description: forbiddenDescription,
            content: jsonErrorContent(
              makeErrorExample(
                403,
                forbiddenMessageExample,
                'Forbidden',
                '/api/v1/example',
              ),
            ),
          }),
        ]
      : []),

    ...(includeTooManyRequests
      ? [
          ApiTooManyRequestsResponse({
            description: tooManyRequestsDescription,
            content: jsonErrorContent(
              makeErrorExample(
                429,
                tooManyRequestsMessageExample,
                'Too Many Requests',
                '/api/v1/example',
              ),
            ),
          }),
        ]
      : []),

    ...(includeInternal
      ? [
          ApiInternalServerErrorResponse({
            description: internalDescription,
            content: jsonErrorContent(
              makeErrorExample(
                500,
                internalMessageExample,
                'Internal Server Error',
                '/api/v1/example',
              ),
            ),
          }),
        ]
      : []),
  ];

  return applyDecorators(...decorators);
}
