import type { Role, User } from '@prisma/client';
import type { CreateUserDto } from 'src/users/dto/create-user.dto';

export type AuthUserSnapshot = {
  id: string;
  email: string;
  role: Role;
};

export interface AuthUsersPort {
  findByEmail(email: string): Promise<User | null>;
  findById(id: string): Promise<User | null>;
  createUser(dto: CreateUserDto): Promise<User>;
  getAuthSnapshotById(userId: string): Promise<AuthUserSnapshot | null>;
}
