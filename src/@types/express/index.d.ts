import type { UserFromJwt } from 'src/common/security/types/user-from-jwt';

declare global {
  namespace Express {
    // eslint-disable-next-line @typescript-eslint/no-empty-object-type
    interface User extends UserFromJwt {}

    interface Request {
      user?: User;
      cookies?: Record<string, unknown>;
      signedCookies?: Record<string, unknown>;
    }
  }
}

export {};
