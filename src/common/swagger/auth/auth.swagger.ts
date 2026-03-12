import {
  SWAGGER_CSRF_COOKIE_NAME_PLACEHOLDER,
  SWAGGER_CSRF_HEADER_NAME_PLACEHOLDER,
  SWAGGER_REFRESH_COOKIE_NAME_PLACEHOLDER,
} from './auth.placeholders';

export const AUTH_SIDE_EFFECTS: Record<
  'register' | 'login' | 'refresh' | 'logout' | 'getMe',
  string[]
> = {
  register: [
    'Створення нового користувача',
    'Створення першої сесії',
    'Видача access/refresh токенів',
    'Збереження refresh token (hash) у БД',
  ],

  login: [
    'Перевірка облікових даних',
    'Скидання лічильників невдалих входів (при успіху)',
    'Відкликання попередніх refresh токенів',
    'Завершення активних сесій користувача',
    'Створення нової сесії',
    'Видача access/refresh токенів',
  ],

  refresh: [
    'Перевірка refresh токена (підпис/issuer/audience/exp)',
    'Перевірка активності сесії (sid)',
    'Перевірка fingerprint (IP/UA) за налаштуваннями',
    'Одноразовий “claim” refresh token (revoke попереднього jti)',
    'Оновлення прив’язки активної сесії до нового jti refresh-токена',
    'Видача нових access/refresh токенів',
  ],

  logout: [
    'Відкликання всіх refresh токенів користувача',
    'Завершення всіх активних сесій користувача',
  ],

  getMe: ['Читання профілю користувача з БД (за userId із access token)'],
};

export const AUTH_SWAGGER_NOTES = {
  csrfIssue: [
    `Sets ${SWAGGER_CSRF_COOKIE_NAME_PLACEHOLDER} cookie (signed, non-HttpOnly, short-lived)`,
    `Returns ${SWAGGER_CSRF_COOKIE_NAME_PLACEHOLDER} in JSON body for ${SWAGGER_CSRF_HEADER_NAME_PLACEHOLDER} header (do not read from cookie)`,
  ],
  refresh: [
    'Refresh має rate limit (Throttle).',
    'При reuse/revoked повертається 401.',
    'Refresh “claim” одноразовий: попередній jti відкликається та його сесія завершується.',
    `Оновлюється лише ${SWAGGER_REFRESH_COOKIE_NAME_PLACEHOLDER} cookie; ${SWAGGER_CSRF_COOKIE_NAME_PLACEHOLDER} cookie не змінюється.`,
  ],
} as const;
