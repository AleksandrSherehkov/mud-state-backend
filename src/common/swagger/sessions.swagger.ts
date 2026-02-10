export const SESSIONS_SIDE_EFFECTS = {
  mySessions: [
    'Повертає список сесій користувача (active + inactive).',
    'Дані беруться з БД по userId із access token.',
  ],

  terminateOthers: [
    'Завершує всі активні сесії користувача, крім поточної (sid з JWT).',
    'Разом із завершенням сесій відкликаються refresh-токени, пов’язані з цими сесіями.',
  ],

  terminateSpecific: [
    'Завершує конкретну сесію користувача за (userId + sessionId).',
    'Разом із завершенням сесії відкликається refresh-токен, пов’язаний з цією сесією.',
  ],

  getUserSessions: [
    'Повертає сесії вказаного користувача за userId.',
    'Доступно лише для ролей ADMIN/MODERATOR.',
  ],
};
