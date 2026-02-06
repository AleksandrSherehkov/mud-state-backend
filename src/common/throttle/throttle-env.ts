function num(name: string, def: number): number {
  const raw = process.env[name];
  if (raw === undefined) return def;

  const v = Number(raw);
  return Number.isFinite(v) && v > 0 ? v : def;
}

export const THROTTLE_AUTH = {
  login: {
    limit: num('THROTTLE_AUTH_LOGIN_LIMIT', 5),
    ttl: num('THROTTLE_AUTH_LOGIN_TTL_SEC', 60),
  },
  register: {
    limit: num('THROTTLE_AUTH_REGISTER_LIMIT', 3),
    ttl: num('THROTTLE_AUTH_REGISTER_TTL_SEC', 60),
  },
  refresh: {
    limit: num('THROTTLE_AUTH_REFRESH_LIMIT', 10),
    ttl: num('THROTTLE_AUTH_REFRESH_TTL_SEC', 60),
  },
  csrf: {
    limit: num('THROTTLE_AUTH_CSRF_LIMIT', 60),
    ttl: num('THROTTLE_AUTH_CSRF_TTL_SEC', 60),
  },
  logout: {
    limit: num('THROTTLE_AUTH_LOGOUT_LIMIT', 3),
    ttl: num('THROTTLE_AUTH_LOGOUT_TTL_SEC', 60),
  },
  me: {
    limit: num('THROTTLE_AUTH_ME_LIMIT', 30),
    ttl: num('THROTTLE_AUTH_ME_TTL_SEC', 60),
  },
} as const;

export const THROTTLE_USERS = {
  byId: {
    limit: num('THROTTLE_USERS_BY_ID_LIMIT', 60),
    ttl: num('THROTTLE_USERS_BY_ID_TTL_SEC', 60),
  },
  byEmail: {
    limit: num('THROTTLE_USERS_BY_EMAIL_LIMIT', 20),
    ttl: num('THROTTLE_USERS_BY_EMAIL_TTL_SEC', 60),
  },
  update: {
    limit: num('THROTTLE_USERS_UPDATE_LIMIT', 20),
    ttl: num('THROTTLE_USERS_UPDATE_TTL_SEC', 60),
  },
  delete: {
    limit: num('THROTTLE_USERS_DELETE_LIMIT', 10),
    ttl: num('THROTTLE_USERS_DELETE_TTL_SEC', 60),
  },
} as const;

export const THROTTLE_SESSIONS = {
  me: {
    limit: num('THROTTLE_SESSIONS_ME_LIMIT', 60),
    ttl: num('THROTTLE_SESSIONS_ME_TTL_SEC', 60),
  },
  terminateOthers: {
    limit: num('THROTTLE_SESSIONS_TERMINATE_OTHERS_LIMIT', 10),
    ttl: num('THROTTLE_SESSIONS_TERMINATE_OTHERS_TTL_SEC', 60),
  },
  terminate: {
    limit: num('THROTTLE_SESSIONS_TERMINATE_LIMIT', 20),
    ttl: num('THROTTLE_SESSIONS_TERMINATE_TTL_SEC', 60),
  },
  getUser: {
    limit: num('THROTTLE_SESSIONS_GET_USER_LIMIT', 60),
    ttl: num('THROTTLE_SESSIONS_GET_USER_TTL_SEC', 60),
  },
} as const;
