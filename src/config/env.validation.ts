import * as Joi from 'joi';

export const envValidationSchema = Joi.object({
  APP_ENV: Joi.string()
    .valid('development', 'production', 'test')
    .default('development'),

  DATABASE_URL: Joi.string().required(),

  API_PREFIX: Joi.string().default('api'),
  API_VERSION: Joi.string().pattern(/^\d+$/).default('1'),

  JWT_ACCESS_SECRET: Joi.string().min(32).required(),
  JWT_REFRESH_SECRET: Joi.string().min(32).required(),
  JWT_ISSUER: Joi.string().min(1).required(),
  JWT_AUDIENCE: Joi.string().min(1).required(),
  JWT_ACCESS_EXPIRES_IN: Joi.string().default('15m'),
  JWT_REFRESH_EXPIRES_IN: Joi.string().default('7d'),

  PORT: Joi.number().default(3000),
  BASE_URL: Joi.string().uri().default('http://localhost:3000'),

  BCRYPT_SALT_ROUNDS: Joi.number().default(10),

  // throttler global
  THROTTLE_TTL_SEC: Joi.number().integer().min(1).max(3600).default(60),
  THROTTLE_LIMIT: Joi.number().integer().min(1).max(10000).default(100),

  // auth throttles
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

  // users throttles
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

  // sessions throttles
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

  // logging
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

  TOKEN_CLEANUP_DAYS: Joi.number().min(1).max(365).default(7),
  TOKEN_CLEANUP_CRON: Joi.string()
    .pattern(/^(\S+\s+){4}\S+$/)
    .default('0 0 * * *'),

  REFRESH_TOKEN_PEPPER: Joi.string().length(64).hex().required(),
  REFRESH_BIND_UA: Joi.boolean().default(true),
  REFRESH_BIND_IP: Joi.boolean().default(false),

  AUTH_LOCK_MAX_ATTEMPTS: Joi.number().min(3).max(50).default(10),
  AUTH_LOCK_BASE_SECONDS: Joi.number().min(1).max(60).default(2),
  AUTH_LOCK_MAX_SECONDS: Joi.number().min(10).max(3600).default(300),
  AUTH_LOCK_WINDOW_SECONDS: Joi.number().min(60).max(86400).default(900),

  PASSWORD_MIN_LENGTH: Joi.number().min(6).max(128).default(8),
  PASSWORD_MAX_LENGTH: Joi.number()
    .min(Joi.ref('PASSWORD_MIN_LENGTH'))
    .max(128)
    .default(72),
  PASSWORD_REQUIRE_UPPERCASE: Joi.boolean().default(true),
  PASSWORD_REQUIRE_DIGIT: Joi.boolean().default(true),
  PASSWORD_REQUIRE_SPECIAL: Joi.boolean().default(false),

  CORS_ORIGINS: Joi.when('APP_ENV', {
    is: 'production',
    then: Joi.string().min(1).required(),
    otherwise: Joi.string().default(''),
  }),
  CORS_ALLOW_NO_ORIGIN: Joi.when('APP_ENV', {
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

  CSRF_TRUSTED_ORIGINS: Joi.when('APP_ENV', {
    is: 'production',
    then: Joi.string().min(1).required(),
    otherwise: Joi.string().default(''),
  }),
  CSRF_API_KEY: Joi.string().min(32).required(),

  TRUST_PROXY_HOPS: Joi.number().integer().min(0).max(10).default(1),

  SWAGGER_ENABLED: Joi.boolean().default(true),

  AUTH_DUMMY_PASSWORD_HASH: Joi.string().min(20).optional(),
  COOKIE_SECRET: Joi.string().min(32).required(),
})
  .unknown(true)
  .prefs({ abortEarly: false });
