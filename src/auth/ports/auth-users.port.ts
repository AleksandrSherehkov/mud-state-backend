import type { Role, User } from '@prisma/client';

export type AuthUserSnapshot = {
  id: string;
  email: string;
  role: Role;
};

export type AuthCreateUserInput = {
  email: string;
  password: string;
};

export interface AuthUsersPort {
  findByEmail(email: string): Promise<User | null>;
  findById(id: string): Promise<User | null>;
  createUser(dto: AuthCreateUserInput): Promise<User>;
  getAuthSnapshotById(userId: string): Promise<AuthUserSnapshot | null>;
}
