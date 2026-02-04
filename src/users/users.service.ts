import {
  Injectable,
  ConflictException,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { Prisma, User } from '@prisma/client';
import { CreateUserDto } from './dto/create-user.dto';
import { ConfigService } from '@nestjs/config';
import { UpdateUserDto } from './dto/update-user.dto';
import { AppLogger } from 'src/logger/logger.service';
import { hashId } from 'src/common/helpers/log-sanitize';

function errMeta(err: unknown) {
  if (err instanceof Error) {
    return { errorName: err.name, errorMessage: err.message };
  }
  return { errorName: 'UnknownError', errorMessage: String(err) };
}

@Injectable()
export class UsersService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly logger: AppLogger,
  ) {
    this.logger.setContext(UsersService.name);
  }

  private normalizeEmail(email: string): string {
    return email.trim().toLowerCase();
  }

  private async hashPassword(password: string): Promise<string> {
    const roundsStr = this.config.get<string>('BCRYPT_SALT_ROUNDS') ?? '10';
    const saltRounds = Number.parseInt(roundsStr, 10);
    const safeRounds = Number.isFinite(saltRounds) ? saltRounds : 10;

    this.logger.debug('Hashing password', UsersService.name, {
      event: 'user.password_hash.start',
      saltRounds: safeRounds,
    });

    return bcrypt.hash(password, safeRounds);
  }

  async createUser(dto: CreateUserDto): Promise<User> {
    const email = this.normalizeEmail(dto.email);
    const emailHash = hashId(email);

    this.logger.log('Create user start', UsersService.name, {
      event: 'user.create.start',
      emailHash,
    });

    const existing = await this.prisma.user.findUnique({
      where: { email },
    });

    if (existing) {
      this.logger.warn(
        'Create user conflict: email exists',
        UsersService.name,
        {
          event: 'user.create.conflict',
          emailHash,
          userId: existing.id,
        },
      );
      throw new ConflictException('Електронна адреса вже використовується');
    }

    const hash = await this.hashPassword(dto.password);

    const created = await this.prisma.user.create({
      data: {
        email,
        password: hash,
      },
    });

    this.logger.log('User created', UsersService.name, {
      event: 'user.create.success',
      userId: created.id,
      emailHash,
      role: created.role,
    });

    return created;
  }

  async findByEmail(email: string): Promise<User | null> {
    const normalized = this.normalizeEmail(email);
    const emailHash = hashId(normalized);

    this.logger.debug('Find user by email', UsersService.name, {
      event: 'user.find_by_email',
      emailHash,
    });

    return this.prisma.user.findUnique({
      where: { email: normalized },
    });
  }

  async findById(id: string): Promise<User | null> {
    this.logger.debug('Find user by id', UsersService.name, {
      event: 'user.find_by_id',
      userId: id,
    });

    return this.prisma.user.findUnique({ where: { id } });
  }

  async updateUser(id: string, dto: UpdateUserDto): Promise<User> {
    const { email, password, role } = dto;
    const data: Partial<User> = {};

    const changes: string[] = [];
    if (email) changes.push('email');
    if (password) changes.push('password');
    if (role) changes.push('role');

    this.logger.log('Update user start', UsersService.name, {
      event: 'user.update.start',
      userId: id,
      changes,
    });

    if (email) data.email = this.normalizeEmail(email);
    if (role) data.role = role;
    if (password) data.password = await this.hashPassword(password);

    try {
      const updated = await this.prisma.user.update({
        where: { id },
        data,
      });

      this.logger.log('User updated', UsersService.name, {
        event: 'user.update.success',
        userId: updated.id,
        role: updated.role,
        emailHash: hashId(updated.email),
        changes,
      });

      return updated;
    } catch (err: unknown) {
      if (err instanceof Prisma.PrismaClientKnownRequestError) {
        if (err.code === 'P2002') {
          this.logger.warn(
            'Update user conflict: email duplicate',
            UsersService.name,
            {
              event: 'user.update.conflict',
              userId: id,
              changes,
              ...errMeta(err),
            },
          );
          throw new ConflictException('Email вже використовується');
        }
        if (err.code === 'P2025') {
          this.logger.warn('Update user not found', UsersService.name, {
            event: 'user.update.not_found',
            userId: id,
            changes,
            ...errMeta(err),
          });
          throw new NotFoundException('Користувача не знайдено');
        }
      }

      this.logger.error('Update user failed', undefined, UsersService.name, {
        event: 'user.update.fail',
        userId: id,
        changes,
        ...errMeta(err),
      });
      throw err;
    }
  }

  async deleteUser(id: string): Promise<User> {
    this.logger.log('Delete user start', UsersService.name, {
      event: 'user.delete.start',
      userId: id,
    });

    try {
      const deleted = await this.prisma.user.delete({
        where: { id },
      });

      this.logger.log('User deleted', UsersService.name, {
        event: 'user.delete.success',
        userId: deleted.id,
        emailHash: hashId(deleted.email),
      });

      return deleted;
    } catch (err: unknown) {
      if (
        err instanceof Prisma.PrismaClientKnownRequestError &&
        err.code === 'P2025'
      ) {
        this.logger.warn('Delete user not found', UsersService.name, {
          event: 'user.delete.not_found',
          userId: id,
          ...errMeta(err),
        });
        throw new NotFoundException('Користувача не знайдено');
      }

      this.logger.error('Delete user failed', undefined, UsersService.name, {
        event: 'user.delete.fail',
        userId: id,
        ...errMeta(err),
      });
      throw err;
    }
  }

  async getAuthSnapshotById(
    id: string,
  ): Promise<{ id: string; email: string; role: User['role'] } | null> {
    this.logger.debug('Get auth snapshot by id', UsersService.name, {
      event: 'user.auth_snapshot.by_id',
      userId: id,
    });

    return this.prisma.user.findUnique({
      where: { id },
      select: { id: true, email: true, role: true },
    });
  }
}
