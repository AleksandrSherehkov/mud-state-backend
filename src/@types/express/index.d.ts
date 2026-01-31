import 'express';
import { UserFromJwt } from 'src/common/types/user-from-jwt';

declare module 'express' {
  interface Request {
    user?: UserFromJwt;
  }
}
