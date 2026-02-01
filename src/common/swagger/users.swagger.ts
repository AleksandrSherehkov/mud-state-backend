export const USERS_SIDE_EFFECTS: Record<
  'getById' | 'getByEmail' | 'update' | 'delete',
  string[]
> = {
  getById: ['Читання користувача з БД за ID'],

  getByEmail: ['Пошук користувача в БД за email'],

  update: [
    'Оновлення даних користувача (partial update)',
    'Можливе хешування пароля (якщо пароль змінюється)',
    'Зміна ролі (якщо передано role)',
  ],

  delete: ['Видалення користувача з БД (незворотно)'],
};
