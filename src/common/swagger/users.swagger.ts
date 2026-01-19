export const USERS_SIDE_EFFECTS = {
  getById: 'Side effects відсутні: лише читання профілю користувача.',

  getByEmail: [
    'Side effects відсутні: лише читання профілю користувача.',
    'Email нормалізується на рівні DTO (trim).',
    'Пошук у сервісі виконується по normalizeEmail (trim + lowercase).',
  ].join('\n'),

  update: [
    'Оновлює поля користувача (email/password/role) у БД.',
    'Email (якщо переданий) нормалізується: trim + lowercase.',
    'Password (якщо переданий) буде перехешовано (bcrypt).',
    'Може завершитися Conflict (email дублюється).',
  ].join('\n'),

  delete: [
    'Видаляє користувача з БД за UUID.',
    'Повертає публічні дані видаленого користувача.',
  ].join('\n'),
} as const;
