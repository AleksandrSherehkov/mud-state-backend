import { Role } from '@prisma/client';

export type UserFromJwt = {
  userId: string;
  email: string;
  role: Role;
  sid: string;
};
