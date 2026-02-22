import * as Joi from 'joi';

export const envValidationSchema = Joi.object({
  APP_ENV: Joi.string()
    .valid('development', 'production', 'test')
    .default('development'),

  PORT: Joi.number().default(3000),

  BASE_URL: Joi.when('APP_ENV', {
    is: 'production',
    then: Joi.string()
      .uri({ scheme: ['https'] })
      .required(),
    otherwise: Joi.string().uri().default('http://localhost:3000'),
  }),

  DATABASE_URL: Joi.string().required(),

  API_PREFIX: Joi.string().default('api'),
  API_VERSION: Joi.string().pattern(/^\d+$/).default('1'),

  SWAGGER_ENABLED: Joi.boolean().default(false),

  // ===== JWT / Tokens =====
  JWT_ACCESS_SECRET: Joi.string().min(32).required(),
  JWT_REFRESH_SECRET: Joi.string().min(32).required(),

  JWT_ISSUER: Joi.string().min(1).required(),
  JWT_AUDIENCE: Joi.string().min(1).required(),

  JWT_ACCESS_EXPIRES_IN: Joi.string().default('10m'),
  JWT_REFRESH_EXPIRES_IN: Joi.string().default('7d'),

  REFRESH_TOKEN_PEPPER: Joi.string().length(64).hex().required(),

  // ===== Session binding & anomaly policy =====
  ACCESS_BIND_UA: Joi.boolean().default(true),
  ACCESS_BIND_IP: Joi.boolean().default(false),

  REFRESH_BIND_UA: Joi.boolean().default(true),
  REFRESH_BIND_IP: Joi.boolean().default(false),

  // ===== Refresh incident strategy (blast radius) =====
  // scoped   - revoke only presented jti + terminate only that session (availability-friendly)
  // user_wide - revoke all refresh tokens + terminate all sessions (paranoid)
  REFRESH_INCIDENT_STRATEGY: Joi.string()
    .valid('scoped', 'user_wide')
    .default('scoped'),

  // ===== Adaptive refresh reuse incident response =====
  REFRESH_REUSE_ADAPTIVE_ENABLED: Joi.boolean().default(true),

  // CSV roles: ADMIN,MODERATOR,USER
  REFRESH_REUSE_ESCALATE_ROLES: Joi.string()
    .trim()
    .pattern(/^(ADMIN|MODERATOR|USER)(,(ADMIN|MODERATOR|USER))*$/i)
    .default('ADMIN,MODERATOR'),

  REFRESH_REUSE_ESCALATE_ON_GEO_ASN: Joi.boolean().default(true),

  REFRESH_REUSE_REPEAT_WINDOW_SEC: Joi.number()
    .integer()
    .min(60)
    .max(86400)
    .default(900),

  REFRESH_REUSE_REPEAT_THRESHOLD: Joi.number()
    .integer()
    .min(2)
    .max(10)
    .default(2),
  ACCESS_FINGERPRINT_MISMATCH_ACTION: Joi.when('APP_ENV', {
    is: 'production',
    then: Joi.string().valid('terminate', 'deny', 'log').default('terminate'),
    otherwise: Joi.string().valid('terminate', 'deny', 'log').default('log'),
  }),

  ACCESS_GEO_ASN_ANOMALY_ACTION: Joi.when('APP_ENV', {
    is: 'production',
    then: Joi.string().valid('terminate', 'deny', 'log').default('terminate'),
    otherwise: Joi.string().valid('terminate', 'deny', 'log').default('log'),
  }),

  ACCESS_ANOMALY_LOG: Joi.boolean().default(true),

  // ===== Adaptive access anomaly response (context-aware) =====
  ACCESS_ANOMALY_ADAPTIVE_ENABLED: Joi.boolean().default(true),

  // CSV roles: ADMIN,MODERATOR,USER
  ACCESS_ANOMALY_ESCALATE_ROLES: Joi.string()
    .trim()
    .pattern(/^(ADMIN|MODERATOR|USER)(,(ADMIN|MODERATOR|USER))*$/i)
    .default('ADMIN,MODERATOR'),

  ACCESS_ANOMALY_ESCALATE_ON_GEO_ASN: Joi.boolean().default(true),

  ACCESS_ANOMALY_REPEAT_WINDOW_SEC: Joi.number()
    .integer()
    .min(60)
    .max(86400)
    .default(900),

  ACCESS_ANOMALY_REPEAT_THRESHOLD: Joi.number()
    .integer()
    .min(2)
    .max(10)
    .default(2),

  AUTH_MAX_ACTIVE_SESSIONS: Joi.number().integer().min(1).max(50).default(1),

  // ===== Password hashing =====
  BCRYPT_SALT_ROUNDS: Joi.number().integer().min(10).max(15).default(12),

  // ===== Global throttler =====
  THROTTLE_TTL_SEC: Joi.number().integer().min(1).max(3600).default(60),
  THROTTLE_LIMIT: Joi.number().integer().min(1).max(10000).default(100),

  THROTTLE_REDIS_URL: Joi.string().min(1).required(),
  THROTTLE_REDIS_PREFIX: Joi.string().default('throttle:'),

  THROTTLE_REDIS_HEALTHCHECK: Joi.boolean().default(true),
  THROTTLE_REDIS_HEALTHCHECK_TIMEOUT_MS: Joi.number()
    .integer()
    .min(100)
    .max(10_000)
    .default(1000),

  // ✅ По-взрослому: strict в prod true, в dev false
  THROTTLE_REDIS_HEALTHCHECK_STRICT: Joi.when('APP_ENV', {
    is: 'production',
    then: Joi.boolean().valid(true).default(true),
    otherwise: Joi.boolean().default(false),
  }),

  THROTTLE_STORE_DRIVER: Joi.when('APP_ENV', {
    is: 'production',
    then: Joi.string().valid('redis').required(),
    otherwise: Joi.string().valid('redis', 'memory').default('redis'),
  }),

  THROTTLE_STORE_MAX_KEYS: Joi.number()
    .integer()
    .min(1000)
    .max(1_000_000)
    .default(50_000),

  THROTTLE_STORE_CLEANUP_INTERVAL_SEC: Joi.number()
    .integer()
    .min(10)
    .max(3600)
    .default(60),

  THROTTLE_STORE_MAX_TTL_SEC: Joi.number()
    .integer()
    .min(1)
    .max(3600)
    .default(300),

  // ===== Per-route throttles (auth) =====
  THROTTLE_AUTH_LOGIN_LIMIT: Joi.number().integer().min(1).max(1000).default(5),
  THROTTLE_AUTH_LOGIN_TTL_SEC: Joi.number()
    .integer()
    .min(1)
    .max(3600)
    .default(60),

  THROTTLE_AUTH_REGISTER_LIMIT: Joi.number()
    .integer()
    .min(1)
    .max(1000)
    .default(3),
  THROTTLE_AUTH_REGISTER_TTL_SEC: Joi.number()
    .integer()
    .min(1)
    .max(3600)
    .default(60),

  THROTTLE_AUTH_REFRESH_LIMIT: Joi.number()
    .integer()
    .min(1)
    .max(10000)
    .default(10),
  THROTTLE_AUTH_REFRESH_TTL_SEC: Joi.number()
    .integer()
    .min(1)
    .max(3600)
    .default(60),

  THROTTLE_AUTH_CSRF_LIMIT: Joi.number()
    .integer()
    .min(1)
    .max(10000)
    .default(60),
  THROTTLE_AUTH_CSRF_TTL_SEC: Joi.number()
    .integer()
    .min(1)
    .max(3600)
    .default(60),

  THROTTLE_AUTH_LOGOUT_LIMIT: Joi.number()
    .integer()
    .min(1)
    .max(1000)
    .default(3),
  THROTTLE_AUTH_LOGOUT_TTL_SEC: Joi.number()
    .integer()
    .min(1)
    .max(3600)
    .default(60),

  THROTTLE_AUTH_ME_LIMIT: Joi.number().integer().min(1).max(10000).default(30),
  THROTTLE_AUTH_ME_TTL_SEC: Joi.number().integer().min(1).max(3600).default(60),

  THROTTLE_AUTH_LOGIN_EMAIL_LIMIT: Joi.number()
    .integer()
    .min(1)
    .max(10000)
    .default(10),
  THROTTLE_AUTH_LOGIN_EMAIL_TTL_SEC: Joi.number()
    .integer()
    .min(1)
    .max(3600)
    .default(300),
  THROTTLE_AUTH_LOGIN_EMAIL_BLOCK_SEC: Joi.number()
    .integer()
    .min(1)
    .max(3600)
    .default(300),

  THROTTLE_AUTH_REGISTER_EMAIL_LIMIT: Joi.number()
    .integer()
    .min(1)
    .max(10000)
    .default(5),
  THROTTLE_AUTH_REGISTER_EMAIL_TTL_SEC: Joi.number()
    .integer()
    .min(1)
    .max(3600)
    .default(600),
  THROTTLE_AUTH_REGISTER_EMAIL_BLOCK_SEC: Joi.number()
    .integer()
    .min(1)
    .max(3600)
    .default(600),

  // ===== Global unauth burst =====
  THROTTLE_UNAUTH_BURST_LIMIT: Joi.number()
    .integer()
    .min(1)
    .max(10000)
    .default(30),
  THROTTLE_UNAUTH_BURST_TTL_SEC: Joi.number()
    .integer()
    .min(1)
    .max(3600)
    .default(10),
  THROTTLE_UNAUTH_BURST_BLOCK_SEC: Joi.number()
    .integer()
    .min(1)
    .max(3600)
    .default(30),

  // ===== Users throttles =====
  THROTTLE_USERS_BY_ID_LIMIT: Joi.number()
    .integer()
    .min(1)
    .max(10000)
    .default(60),
  THROTTLE_USERS_BY_ID_TTL_SEC: Joi.number()
    .integer()
    .min(1)
    .max(3600)
    .default(60),

  THROTTLE_USERS_BY_EMAIL_LIMIT: Joi.number()
    .integer()
    .min(1)
    .max(10000)
    .default(20),
  THROTTLE_USERS_BY_EMAIL_TTL_SEC: Joi.number()
    .integer()
    .min(1)
    .max(3600)
    .default(60),

  THROTTLE_USERS_UPDATE_LIMIT: Joi.number()
    .integer()
    .min(1)
    .max(10000)
    .default(20),
  THROTTLE_USERS_UPDATE_TTL_SEC: Joi.number()
    .integer()
    .min(1)
    .max(3600)
    .default(60),

  THROTTLE_USERS_DELETE_LIMIT: Joi.number()
    .integer()
    .min(1)
    .max(10000)
    .default(10),
  THROTTLE_USERS_DELETE_TTL_SEC: Joi.number()
    .integer()
    .min(1)
    .max(3600)
    .default(60),

  // ===== Sessions throttles =====
  THROTTLE_SESSIONS_ME_LIMIT: Joi.number()
    .integer()
    .min(1)
    .max(10000)
    .default(60),
  THROTTLE_SESSIONS_ME_TTL_SEC: Joi.number()
    .integer()
    .min(1)
    .max(3600)
    .default(60),

  THROTTLE_SESSIONS_TERMINATE_OTHERS_LIMIT: Joi.number()
    .integer()
    .min(1)
    .max(10000)
    .default(10),
  THROTTLE_SESSIONS_TERMINATE_OTHERS_TTL_SEC: Joi.number()
    .integer()
    .min(1)
    .max(3600)
    .default(60),

  THROTTLE_SESSIONS_TERMINATE_LIMIT: Joi.number()
    .integer()
    .min(1)
    .max(10000)
    .default(20),
  THROTTLE_SESSIONS_TERMINATE_TTL_SEC: Joi.number()
    .integer()
    .min(1)
    .max(3600)
    .default(60),

  THROTTLE_SESSIONS_GET_USER_LIMIT: Joi.number()
    .integer()
    .min(1)
    .max(10000)
    .default(60),
  THROTTLE_SESSIONS_GET_USER_TTL_SEC: Joi.number()
    .integer()
    .min(1)
    .max(3600)
    .default(60),

  // ===== Logging =====
  LOG_DIR: Joi.string().default('logs'),
  LOG_FILE_NAME: Joi.string().default('%DATE%.log'),
  LOG_DATE_PATTERN: Joi.string().default('YYYY-MM-DD'),
  LOG_ZIPPED_ARCHIVE: Joi.boolean().default(true),
  LOG_MAX_SIZE: Joi.string().default('10m'),
  LOG_MAX_FILES: Joi.string().default('14d'),
  LOG_LEVEL: Joi.string()
    .valid('error', 'warn', 'info', 'http', 'verbose', 'debug', 'silly')
    .default('debug'),

  PRISMA_LOG_QUERIES: Joi.boolean().default(false),
  PRISMA_QUERY_SAMPLE_RATE: Joi.number().min(0).max(1).default(0.05),

  // ===== Token maintenance =====
  TOKEN_CLEANUP_DAYS: Joi.number().min(1).max(365).default(7),
  TOKEN_CLEANUP_CRON: Joi.string()
    .pattern(/^(\S+\s+){4}\S+$/)
    .default('0 0 * * *'),

  // ===== Auth lock =====
  AUTH_LOCK_MAX_ATTEMPTS: Joi.number().min(3).max(50).default(10),
  AUTH_LOCK_BASE_SECONDS: Joi.number().min(1).max(60).default(2),
  AUTH_LOCK_MAX_SECONDS: Joi.number().min(10).max(3600).default(300),
  AUTH_LOCK_WINDOW_SECONDS: Joi.number().min(60).max(86400).default(900),
  // ===== Adaptive auth challenge (PoW step-up) =====
  AUTH_CHALLENGE_ENABLED: Joi.boolean().default(true),

  // window for counting failed attempts (per id/ip)
  AUTH_CHALLENGE_WINDOW_SEC: Joi.number()
    .integer()
    .min(60)
    .max(86400)
    .default(900),

  // require challenge after N fails in the window
  AUTH_CHALLENGE_AFTER_FAILS: Joi.number().integer().min(1).max(100).default(6),

  // PoW difficulty in leading-zero BITS (tradeoff UX vs defense)
  AUTH_CHALLENGE_DIFFICULTY_BITS: Joi.number()
    .integer()
    .min(12)
    .max(28)
    .default(18),

  // nonce TTL (client has this long to solve)
  AUTH_CHALLENGE_NONCE_TTL_SEC: Joi.number()
    .integer()
    .min(10)
    .max(600)
    .default(120),

  AUTH_CHALLENGE_PREFIX: Joi.string().min(1).default('auth:chal:'),

  // ===== Password policy =====
  PASSWORD_MIN_LENGTH: Joi.number().min(6).max(128).default(8),
  PASSWORD_MAX_LENGTH: Joi.number()
    .min(Joi.ref('PASSWORD_MIN_LENGTH'))
    .max(128)
    .default(72),
  PASSWORD_REQUIRE_UPPERCASE: Joi.boolean().default(true),
  PASSWORD_REQUIRE_DIGIT: Joi.boolean().default(true),
  PASSWORD_REQUIRE_SPECIAL: Joi.boolean().default(false),

  // ===== CORS / CSRF =====
  CORS_ORIGINS: Joi.when('APP_ENV', {
    is: 'production',
    then: Joi.string().min(1).required(),
    otherwise: Joi.string().default(
      'http://localhost:3000,http://127.0.0.1:3000',
    ),
  }),

  CORS_ALLOW_NO_ORIGIN: Joi.when('APP_ENV', {
    is: 'production',
    then: Joi.boolean().valid(false).default(false),
    otherwise: Joi.boolean().default(true),
  }),

  CSRF_TRUSTED_ORIGINS: Joi.when('APP_ENV', {
    is: 'production',
    then: Joi.string().min(1).required(),
    otherwise: Joi.string().default(
      'http://localhost:3000,http://127.0.0.1:3000',
    ),
  }),

  CSRF_ALLOW_NO_ORIGIN: Joi.when('APP_ENV', {
    is: 'production',
    then: Joi.boolean().valid(false).default(false),
    otherwise: Joi.boolean().default(true),
  }),

  COOKIE_SAMESITE: Joi.string().valid('lax', 'strict', 'none').default('lax'),
  COOKIE_CROSS_SITE: Joi.when('COOKIE_SAMESITE', {
    is: 'none',
    then: Joi.boolean().valid(true).required(),
    otherwise: Joi.boolean().default(false),
  }),

  COOKIE_SECRET: Joi.string().min(32).required(),

  // ===== CSRF M2M =====

  CSRF_M2M_SECRETS_FILE: Joi.when('APP_ENV', {
    is: 'production',
    then: Joi.string().min(1).required(),
    otherwise: Joi.string().min(1).optional(),
  }),

  CSRF_M2M_SECRETS_RELOAD_TTL_SEC: Joi.number()
    .integer()
    .min(1)
    .max(3600)
    .default(30),

  CSRF_M2M_REPLAY_WINDOW_SEC: Joi.number()
    .integer()
    .min(10)
    .max(300)
    .default(60),
  CSRF_M2M_REDIS_URL: Joi.string().min(1).optional(),
  CSRF_M2M_NONCE_PREFIX: Joi.string().min(1).default('csrf:m2m:nonce:'),

  CSRF_ENABLED: Joi.boolean().default(true),
  CSRF_COOKIE_NAME: Joi.string().min(1).default('csrfToken'),
  CSRF_HEADER_NAME: Joi.string().min(1).default('x-csrf-token'),

  CSRF_ENFORCE_FETCH_SITE_IN_PROD: Joi.boolean().default(true),
  CSRF_ALLOWED_FETCH_SITES: Joi.string().default('same-origin,same-site'),

  CSRF_M2M_ENABLED: Joi.boolean().default(true),

  // ===== Proxy trust =====
  TRUST_PROXY_HOPS: Joi.when('APP_ENV', {
    is: 'production',
    then: Joi.number().integer().min(1).max(10).required(),
    otherwise: Joi.number().integer().min(0).max(10).default(0),
  }),

  TRUST_PROXY_GEO_HEADERS: Joi.boolean().default(false),

  TRUSTED_PROXY_IPS: Joi.when('TRUST_PROXY_GEO_HEADERS', {
    is: true,
    then: Joi.string().min(1).required(),
    otherwise: Joi.string().optional(),
  }),

  TRUST_PROXY_GEO_MARKER_NAME: Joi.when('TRUST_PROXY_GEO_HEADERS', {
    is: true,
    then: Joi.string().default('x-ingress-auth'),
    otherwise: Joi.string().optional(),
  }),

  TRUST_PROXY_GEO_MARKER_VALUE: Joi.when('TRUST_PROXY_GEO_HEADERS', {
    is: true,
    then: Joi.string().min(1).default('1'),
    otherwise: Joi.string().optional(),
  }),

  AUTH_DUMMY_PASSWORD_HASH: Joi.string().min(20).optional(),
})
  .unknown(true)
  .prefs({ abortEarly: false });
