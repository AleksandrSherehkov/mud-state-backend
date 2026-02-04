import type { Request } from 'express';
import { getCookieString } from 'src/common/http/cookies';

const REFRESH_COOKIE_NAME = 'refreshToken';

export function getRefreshTokenFromRequest(req: Request): string | undefined {
  return getCookieString(req, REFRESH_COOKIE_NAME, { signed: true });
}
