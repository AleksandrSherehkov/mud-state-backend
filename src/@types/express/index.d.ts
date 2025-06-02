import 'express';
import { UserFromJwt } from 'src/auth/types/user-from-jwt';

declare module 'express' {
  interface Request {
    user?: UserFromJwt & { role: string };
  }
}
