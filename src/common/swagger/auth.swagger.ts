export const AUTH_SIDE_EFFECTS = {
  register: [
    'Створює нового користувача в БД.',
    'Створює refresh-токен (RefreshToken) з новим jti та зберігає tokenHash (refresh JWT у БД не зберігається).',
    'Створює сесію (Session) та прив’язує її до refreshTokenId=jti.',
    'Повертає accessToken + refreshToken + jti.',
  ].join('\n'),

  login: [
    'Перевіряє email/password.',
    'Відкликає всі активні refresh-токени користувача (revokeAll).',
    'Завершує всі активні сесії користувача (terminateAll).',
    'Створює refresh-токен (RefreshToken) з новим jti та зберігає tokenHash (refresh JWT у БД не зберігається).',
    'Створює нову сесію (Session) та прив’язує її до refreshTokenId=jti.',
    'Повертає accessToken + refreshToken + jti.',
  ].join('\n'),

  refresh: [
    'Верифікує refresh JWT (підпис/exp) та перевіряє відповідність userId (sub).',
    'Atomically “claim”: відкликає refresh-токен по (jti + userId + tokenHash), де tokenHash = SHA256(pepper + refreshToken). Якщо hash не співпав або токен уже відкликаний/повторно використаний — 401.',
    'Завершує сесію, пов’язану з попереднім jti (terminateByRefreshToken).',
    'Створює новий refresh-токен (новий jti) та нову сесію (Session) з прив’язкою до refreshTokenId=jti.',
    'Повертає нові accessToken + refreshToken + jti.',
  ].join('\n'),

  logout: [
    'Відкликає всі активні refresh-токени користувача (revokeAll).',
    'Завершує всі активні сесії користувача (terminateAll).',
    'Якщо немає що відкликати/завершити — повертає noop (у тебе це BadRequest на рівні контролера).',
  ].join('\n'),

  getMe: 'Side effects відсутні: лише читання профілю.',
  getUserSessions:
    'Side effects відсутні: лише читання активних refresh-токенів (revoked=false).',
  getActiveSessions: 'Side effects відсутні: лише читання активних сесій.',
  getMySessions: 'Side effects відсутні: лише читання всіх сесій.',

  terminateOtherSessions: [
    'Завершує всі активні сесії користувача, крім поточної (exclude sid з JWT).',
    'Refresh-токени не відкликає.',
  ].join('\n'),

  terminateSpecificSession: [
    'Завершує активну сесію користувача, знайдену за парою IP + User-Agent.',
    'Refresh-токени не відкликає.',
  ].join('\n'),
} as const;
