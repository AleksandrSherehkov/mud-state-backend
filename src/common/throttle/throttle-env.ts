function num(name: string, def: number): number {
  const raw = process.env[name];
  if (raw === undefined) return def;

  const v = Number(raw);
  return Number.isFinite(v) && v > 0 ? v : def;
}

const THROTTLE_STORE_MAX_TTL_SEC = num('THROTTLE_STORE_MAX_TTL_SEC', 300);

function ttl(name: string, def: number): number {
  return Math.min(num(name, def), THROTTLE_STORE_MAX_TTL_SEC);
}

export const THROTTLE_AUTH = {
  loginIp: {
    limit: num('THROTTLE_AUTH_LOGIN_LIMIT', 5),
    ttl: ttl('THROTTLE_AUTH_LOGIN_TTL_SEC', 60),
  },
  loginAccount: {
    limit: num('THROTTLE_AUTH_LOGIN_ACCOUNT_LIMIT', 5),
    ttl: ttl('THROTTLE_AUTH_LOGIN_ACCOUNT_TTL_SEC', 300),
  },
  loginDevice: {
    limit: num('THROTTLE_AUTH_LOGIN_DEVICE_LIMIT', 20),
    ttl: ttl('THROTTLE_AUTH_LOGIN_DEVICE_TTL_SEC', 300),
  },
  registerIp: {
    limit: num('THROTTLE_AUTH_REGISTER_LIMIT', 3),
    ttl: ttl('THROTTLE_AUTH_REGISTER_TTL_SEC', 60),
  },
  registerAccount: {
    limit: num('THROTTLE_AUTH_REGISTER_ACCOUNT_LIMIT', 3),
    ttl: ttl('THROTTLE_AUTH_REGISTER_ACCOUNT_TTL_SEC', 900),
  },
  registerDevice: {
    limit: num('THROTTLE_AUTH_REGISTER_DEVICE_LIMIT', 10),
    ttl: ttl('THROTTLE_AUTH_REGISTER_DEVICE_TTL_SEC', 900),
  },
  refresh: {
    limit: num('THROTTLE_AUTH_REFRESH_LIMIT', 10),
    ttl: ttl('THROTTLE_AUTH_REFRESH_TTL_SEC', 60),
  },
  csrf: {
    limit: num('THROTTLE_AUTH_CSRF_LIMIT', 60),
    ttl: ttl('THROTTLE_AUTH_CSRF_TTL_SEC', 60),
  },
  logout: {
    limit: num('THROTTLE_AUTH_LOGOUT_LIMIT', 3),
    ttl: ttl('THROTTLE_AUTH_LOGOUT_TTL_SEC', 60),
  },
  me: {
    limit: num('THROTTLE_AUTH_ME_LIMIT', 30),
    ttl: ttl('THROTTLE_AUTH_ME_TTL_SEC', 60),
  },
} as const;

export const THROTTLE_USERS = {
  byId: {
    limit: num('THROTTLE_USERS_BY_ID_LIMIT', 60),
    ttl: ttl('THROTTLE_USERS_BY_ID_TTL_SEC', 60),
  },
  byEmail: {
    limit: num('THROTTLE_USERS_BY_EMAIL_LIMIT', 20),
    ttl: ttl('THROTTLE_USERS_BY_EMAIL_TTL_SEC', 60),
  },
  update: {
    limit: num('THROTTLE_USERS_UPDATE_LIMIT', 20),
    ttl: ttl('THROTTLE_USERS_UPDATE_TTL_SEC', 60),
  },
  delete: {
    limit: num('THROTTLE_USERS_DELETE_LIMIT', 10),
    ttl: ttl('THROTTLE_USERS_DELETE_TTL_SEC', 60),
  },
} as const;

export const THROTTLE_SESSIONS = {
  me: {
    limit: num('THROTTLE_SESSIONS_ME_LIMIT', 60),
    ttl: ttl('THROTTLE_SESSIONS_ME_TTL_SEC', 60),
  },
  terminateOthers: {
    limit: num('THROTTLE_SESSIONS_TERMINATE_OTHERS_LIMIT', 10),
    ttl: ttl('THROTTLE_SESSIONS_TERMINATE_OTHERS_TTL_SEC', 60),
  },
  terminate: {
    limit: num('THROTTLE_SESSIONS_TERMINATE_LIMIT', 20),
    ttl: ttl('THROTTLE_SESSIONS_TERMINATE_TTL_SEC', 60),
  },
  getUser: {
    limit: num('THROTTLE_SESSIONS_GET_USER_LIMIT', 60),
    ttl: ttl('THROTTLE_SESSIONS_GET_USER_TTL_SEC', 60),
  },
} as const;
