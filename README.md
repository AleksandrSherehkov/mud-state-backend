# MUD State Backend

Production-ready NestJS backend для керування автентифікацією, авторизацією та життєвим циклом сесій у stateful API-середовищі.

## 1. Project Overview

### Що робить система

Цей сервіс реалізує:
- реєстрацію та логін користувачів;
- JWT access/refresh модель із ротацією refresh токенів;
- детекцію повторного використання refresh токена (reuse detection);
- керування сесіями (перегляд, завершення поточної/інших, аудит);
- RBAC-модель ролей `ADMIN` / `MODERATOR` / `USER`;
- захист від brute-force та rate limiting;
- структуроване логування для операційної та security-аналітики.

### Ключові архітектурні рішення

1. **Stateful-сесії поверх JWT**: access JWT містить `sid`, але валідність перевіряється через активну сесію в БД; це дозволяє серверне анулювання токенів/сесій до їх `exp`.
2. **Refresh rotation як одноразовий claim**: refresh токен має `jti`; при `POST /auth/refresh` старий токен атомарно claim/revoke, видається новий `jti` і оновлюється звʼязок `session -> refreshTokenJti`.
3. **DB-as-policy**: інваріанти життєвого циклу сесій та часткова унікальність активного `refreshTokenJti` закріплені constraints/indexes у PostgreSQL, а не лише application-логікою.
4. **Defense-in-depth**: CSRF (double-submit + origin policy), throttling, обліковий lockout, fingerprint binding (UA/IP), перевірка geo/ASN аномалій, санітизація логів.

### Чому обрано ці технології

- **NestJS**: модульна архітектура, guard/interceptor/filter pipeline, зручна інтеграція з Swagger.
- **Prisma + PostgreSQL**: типобезпечний доступ до даних + сильні інваріанти на рівні БД.
- **JWT**: компактний bearer для access-потоку + server-side керована refresh модель.
- **Winston**: контрольований structured logging із ротацією файлів та редагуванням чутливих даних.

## 2. Architecture

### High-level

- `AuthModule`: register/login/refresh/logout/csrf/me.
- `SessionsModule`: операції з життєвим циклом сесій, terminate, binding refresh->session.
- `UsersModule`: адміністрування користувачів із role-based доступом.
- `SecurityModule` + guards: CSRF, JWT guard, roles guard, fresh-access guard, throttling guard.
- `LoggerModule`: централізоване безпечне логування.
- `JobsModule`: фонове прибирання токенів.

Глобальні guard-и підключені як `APP_GUARD` у порядку: throttler -> JWT -> roles -> fresh-access.

### Межі модулів

- **Auth** відповідає за видачу та ротацію токенів, але використовує окремі сервіси для транзакцій, безпеки, сесій, refresh-хешування.
- **Sessions** є джерелом істини про активність сесії (`isActive`, `endedAt`, `refreshTokenJti`).
- **Users** не містить auth-логіки; лише управління користувачами та ролями.

### Auth flow (login → refresh → logout → reuse detection)

1. **Login/Register**:
   - перевірка CSRF для mutation endpoint-ів;
   - створення `sid` + `refresh jti`;
   - видача access JWT (Bearer) і refresh cookie (`HttpOnly`, signed).
2. **Refresh**:
   - валідація refresh JWT + перевірка активної сесії;
   - optional fingerprint перевірка (UA/IP);
   - атомарний claim старого refresh + випуск нового + rebind session.
3. **Logout**:
   - revoke усіх refresh токенів користувача + terminate усіх сесій;
   - очищення auth cookies.
4. **Reuse detection**:
   - якщо claim старого `jti` неуспішний (race/replay/revoked), система трактує це як reuse;
   - виконується user-wide response: revoke all refresh + terminate all sessions + `401`.

### Session lifecycle модель

Сесія має два валідні стани:
- `isActive=true` і `endedAt IS NULL`;
- `isActive=false` і `endedAt IS NOT NULL`.

Стан enforce-иться check constraints у БД. Додатково є перевірка `endedAt >= startedAt`.

### Security model overview

- Access token сам по собі недостатній: потрібна активна сесія в БД.
- Refresh token одноразовий по `jti` (rotation + claim).
- Критичні mutation endpoint-и захищені CSRF guard.
- RBAC працює через `@Roles(...)` і глобальний `RolesGuard`.
- Для high-risk операцій застосовується `@RequireFreshAccess(...)` (обмеження за віком access JWT).

## 3. Security Design

### Threat model assumptions

Система припускає, що:
1. TLS термінація коректна і трафік до клієнта захищений HTTPS у production.
2. Секрети (`JWT_*_SECRET`, `REFRESH_TOKEN_PEPPER`, `COOKIE_SECRET`, `CSRF_API_KEY`) не скомпрометовані.
3. `TRUST_PROXY_HOPS` коректно налаштований для реального ланцюга проксі.
4. Клієнт зберігає access token поза cookie (Bearer), refresh токен — у HttpOnly signed cookie.

### Які атаки помʼякшуються

- replay refresh токена;
- brute-force логіну;
- session fixation;
- CSRF для auth cookie mutation endpoint-ів;
- token theft blast radius (через rotation + session checks + reuse response);
- privilege misuse через RBAC та fresh-access на чутливих endpoint-ах.

### JWT flow: access vs refresh

- **Access JWT**: короткоживучий (`JWT_ACCESS_EXPIRES_IN`), передається в `Authorization: Bearer ...`, містить `sub`, `sid`, роль.
- **Refresh JWT**: довший TTL (`JWT_REFRESH_EXPIRES_IN`), зберігається в cookie `refreshToken`, має `jti` для одноразового claim.

### Refresh rotation strategy

- На refresh генерується новий `jti`.
- Старий refresh токен атомарно revocation-claim-иться в транзакції.
- Сесія перебінджується на новий `jti`.

Це робить refresh токен **single-use** і стійким до простого replay.

### Reuse detection policy

Якщо claim не проходить (відсутній/вже revoked/expired/hash mismatch/race), запускається response політика:
- revoke all refresh токенів користувача;
- terminate all сесій;
- повернення `401 Unauthorized`.

### Session invalidation strategy

- Logout: user-wide revoke+terminate.
- Reuse/fingerprint mismatch/аномалії (залежно від policy): scoped або user-wide terminate/revoke.
- Доступ по access JWT блокується, якщо сесія неактивна.

### Replay, brute-force, fixation: чому це безпечніше

- **Replay**: refresh claim + rotation + partial unique active-binding + revoke-on-reuse.
- **Brute-force**: route throttling + account lockout з експоненційною затримкою.
- **Session fixation**: на login/register генеруються нові `sid`/`jti`; немає прийняття клієнтського `sid`.

### Timing-safe comparisons

Порівняння refresh hash виконується через `timingSafeEqual` для hex-буферів, що зменшує ризик timing attack при перевірці токена.

### DB-level invariants

- `session_state_consistency_chk` / `Session_state_invariant` для узгодженості `isActive` та `endedAt`.
- `session_time_consistency_chk` для `endedAt >= startedAt`.
- Частковий унікальний індекс активного `refreshTokenJti` у `Session` (`WHERE isActive=true`).

### OWASP alignment (практично)

- ASVS Session Management: server-side invalidation, rotation, timeout/freshness.
- ASVS Access Control: централізований RBAC guard.
- ASVS V2/V3: credential hardening, lockout, secure cookie policy, CSRF controls.
- Logging: маскування/редакція секретів і токенів.

## 4. API Overview

Базовий шлях: `/{API_PREFIX}/v{API_VERSION}` (за замовчуванням `/api/v1`).

### Auth endpoints

- `POST /auth/register`
- `POST /auth/login`
- `GET /auth/csrf`
- `POST /auth/refresh`
- `POST /auth/logout`
- `GET /auth/me`

### Session endpoints

- `GET /sessions/me`
- `POST /sessions/terminate`
- `POST /sessions/terminate-others`
- `GET /sessions/:userId` (ADMIN/MODERATOR)

### User endpoints

- `GET /users/id/:id` (ADMIN/MODERATOR)
- `GET /users/by-email?email=...` (ADMIN/MODERATOR)
- `PATCH /users/:id` (ADMIN + fresh access)
- `DELETE /users/:id` (ADMIN + fresh access)

### Role protection модель

- `USER`: authenticated доступ до власних auth/session операцій.
- `MODERATOR`: read-only адмінські операції над користувачами/сесіями.
- `ADMIN`: повний доступ, включно з mutate/delete користувачів.

### Swagger/OpenAPI

- Шлях: `/{API_PREFIX}/docs` (типово `/api/docs`).
- Увімкнення через `SWAGGER_ENABLED=true`.
- У production Swagger примусово відключається логікою bootstrap.

## 5. Environment Configuration

### Обовʼязкові змінні (мінімум)

- `DATABASE_URL`
- `JWT_ACCESS_SECRET`
- `JWT_REFRESH_SECRET`
- `JWT_ISSUER`
- `JWT_AUDIENCE`
- `REFRESH_TOKEN_PEPPER` (hex, 64 символи)
- `CSRF_API_KEY`
- `COOKIE_SECRET`
- `CORS_ORIGINS` (обовʼязково в усіх env, wildcard заборонений)

### Чутлива конфігурація

- `REFRESH_TOKEN_PEPPER` використовується у hash-похідній refresh токенів; обертання потребує плану міграції.
- `COOKIE_SAMESITE=none` вимагає `COOKIE_CROSS_SITE=true` і HTTPS.
- `TRUST_PROXY_HOPS` критичний для коректного `req.ip` за reverse proxy.

### Приклад `.env`

```env
APP_ENV=development
PORT=3000
BASE_URL=http://localhost:3000
API_PREFIX=api
API_VERSION=1

DATABASE_URL=postgresql://postgres:postgres@localhost:5432/mud_state

JWT_ACCESS_SECRET=change_me_access_secret_min_32_chars
JWT_REFRESH_SECRET=change_me_refresh_secret_min_32_chars
JWT_ISSUER=mud-state-backend
JWT_AUDIENCE=mud-state-clients
JWT_ACCESS_EXPIRES_IN=10m
JWT_REFRESH_EXPIRES_IN=7d

REFRESH_TOKEN_PEPPER=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
COOKIE_SECRET=change_me_cookie_secret_min_32_chars

CORS_ORIGINS=http://localhost:5173
CORS_ALLOW_NO_ORIGIN=true
CSRF_TRUSTED_ORIGINS=http://localhost:5173
CSRF_API_KEY=change_me_csrf_api_key_min_32_chars

THROTTLE_TTL_SEC=60
THROTTLE_LIMIT=100
THROTTLE_AUTH_LOGIN_LIMIT=5
THROTTLE_AUTH_LOGIN_TTL_SEC=60

AUTH_LOCK_MAX_ATTEMPTS=10
AUTH_LOCK_BASE_SECONDS=2
AUTH_LOCK_MAX_SECONDS=300
AUTH_LOCK_WINDOW_SECONDS=900

SWAGGER_ENABLED=true
```

## 6. Running the Project

### Local development

```bash
npm install
npx prisma generate
npx prisma migrate deploy
npm run start:dev
```

### Docker setup

У поточному стані репозиторію відсутні `Dockerfile`/`docker-compose.yml`, тому контейнерний запуск не може бути відтворений без додавання цих маніфестів.

Рекомендований production pattern:
- multi-stage Docker build (Node 20/22, non-root user);
- окремий контейнер PostgreSQL або managed DB;
- секрети через runtime secret store (не через baked ENV у образі);
- healthcheck endpoint + readiness/liveness у оркестраторі.

### Production considerations

- Вимикайте Swagger.
- Примушуйте HTTPS та HSTS.
- Валідуйте `TRUST_PROXY_HOPS` відповідно до мережевої топології.
- Використовуйте зовнішній centralized log sink.

## 7. Logging & Observability

### Winston стратегія

- Console + daily rotate file transports.
- JSON у файли, структуровані поля (`event`, `userId`, `sid`, `jti`, `requestId`).
- Request correlation через request context middleware/interceptor.

### Що логуються

- auth події (register/login/logout/refresh/reuse/fingerprint anomalies);
- session lifecycle (create/terminate/rebind);
- security policy спрацьовування (lockout, deny/terminate).

### Security вимоги до логів

- токени, cookie, `authorization`, `password`, `secret` та похідні редагуються;
- IP маскується, user-agent хешується в security-подіях;
- уникається логування повних секретів/PII.

## 8. Database

### Prisma schema overview

Основні сутності:
- `User` (`Role` enum, `email` як `citext unique`);
- `RefreshToken` (`jti`, hash+salt, revoked, expiresAt);
- `Session` (стан, binding до refresh token, fingerprint/geo поля);
- `UserSecurity` (лічильники failed login і lockout стан).

### Migration strategy

- міграції версіонуються в `prisma/migrations`;
- `prisma migrate deploy` застосовується в CI/CD;
- SQL-міграції включають backfill перед додаванням constraints, щоб уникати production breakage.

### Важливі обмеження

- email case-insensitive uniqueness (`citext`);
- session state/time consistency checks;
- partial unique index для active refresh binding.

## 9. Testing Strategy

Поточний toolchain має підтримку:
- unit tests (`npm test`);
- e2e (`npm run test:e2e`);
- lint/build для quality gates.

Security readiness для тестів:
- сценарії refresh replay/reuse;
- перевірка lockout-поведінки;
- перевірка CSRF double-submit та origin policy;
- перевірка revoke/terminate після logout.

Примітка: фактичне покриття залежить від наявних test files у `src/**/*.spec.ts` і `test/**/*.e2e-spec.ts`.

## 10. Hardening Notes

Рекомендовано для production:

1. **Reverse proxy**
   - чітко налаштувати `X-Forwarded-*`;
   - встановити правильний `TRUST_PROXY_HOPS`.
2. **HTTPS only**
   - TLS 1.2+;
   - HSTS;
   - жодних HTTP origin у CORS для production.
3. **Cookie policy**
   - `HttpOnly` для refresh;
   - `Secure=true` у production;
   - `SameSite` згідно з архітектурою фронтенду (`none` тільки за HTTPS).
4. **Secrets hygiene**
   - регулярна ротація;
   - зберігання у vault/KMS.

## 11. Future Improvements

1. **Horizontal scaling**
   - винесення throttler storage в Redis;
   - shared session-risk cache між інстансами.
2. **Redis integration**
   - distributed rate limiting;
   - короткоживучі security counters/flags.
3. **Step-up auth / token binding**
   - step-up для high-risk операцій (MFA/WebAuthn);
   - stronger device binding із risk-based policy.
4. **Operational maturity**
   - SIEM інтеграція, alerting rules для reuse/anomaly spikes;
   - SLO + error budget + audit dashboards.

## Відомі обмеження

1. В репозиторії відсутні Docker маніфести (`Dockerfile`, `docker-compose.yml`) — контейнерний шлях слід додати окремо.
2. In-memory throttler storage обмежений, але не підходить для truly distributed multi-node rate limiting без зовнішнього бекенду.
3. Fingerprint binding за IP може бути noisy у мобільних/CGNAT мережах; у production політику слід калібрувати на реальні патерни трафіку.
4. Без компрометації секретів система стійка до replay/фиксації; при витоку секретів потрібен incident response (ротація ключів + invalidate сесій).

## License

MIT
