import { ConflictException, NotFoundException } from '@nestjs/common';
import { Prisma, Role, type User } from '@prisma/client';
import * as bcrypt from 'bcrypt';

import { UsersService } from './users.service';
import type { PrismaService } from '../prisma/prisma.service';
import type { ConfigService } from '@nestjs/config';
import type { AppLogger } from 'src/logger/logger.service';

jest.mock('src/common/helpers/log-sanitize', () => ({
  hashId: jest.fn(() => 'hash'),
}));

type UserFindUniqueArgs = { where: { email?: string; id?: string } };
type UserCreateArgs = { data: { email: string; password: string } };
type UserUpdateArgs = { where: { id: string }; data: Partial<User> };
type UserDeleteArgs = { where: { id: string } };

type RefreshTokenDeleteManyArgs = {
  where: { revoked: boolean; createdAt: { lt: Date } };
};
type SessionDeleteManyArgs = {
  where: { isActive: boolean; endedAt: { lt: Date } };
};

describe('UsersService', () => {
  let service: UsersService;

  let prisma: {
    user: {
      findUnique: jest.Mock<Promise<User | null>, [UserFindUniqueArgs]>;
      create: jest.Mock<Promise<User>, [UserCreateArgs]>;
      update: jest.Mock<Promise<User>, [UserUpdateArgs]>;
      delete: jest.Mock<Promise<User>, [UserDeleteArgs]>;
    };
    refreshToken: {
      deleteMany: jest.Mock<
        Promise<{ count: number }>,
        [RefreshTokenDeleteManyArgs]
      >;
    };
    session: {
      deleteMany: jest.Mock<
        Promise<{ count: number }>,
        [SessionDeleteManyArgs]
      >;
    };
  };

  let config: {
    get: jest.Mock<string | undefined, [key: string]>;
  };

  let logger: jest.Mocked<
    Pick<AppLogger, 'setContext' | 'log' | 'warn' | 'error' | 'debug'>
  >;

  beforeEach(() => {
    jest.clearAllMocks();

    prisma = {
      user: {
        findUnique: jest.fn<Promise<User | null>, [UserFindUniqueArgs]>(),
        create: jest.fn<Promise<User>, [UserCreateArgs]>(),
        update: jest.fn<Promise<User>, [UserUpdateArgs]>(),
        delete: jest.fn<Promise<User>, [UserDeleteArgs]>(),
      },
      refreshToken: {
        deleteMany: jest.fn<
          Promise<{ count: number }>,
          [RefreshTokenDeleteManyArgs]
        >(),
      },
      session: {
        deleteMany: jest.fn<
          Promise<{ count: number }>,
          [SessionDeleteManyArgs]
        >(),
      },
    };

    config = {
      get: jest.fn<string | undefined, [key: string]>(),
    };

    logger = {
      setContext: jest.fn(),
      log: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
      debug: jest.fn(),
    };

    service = new UsersService(
      prisma as unknown as PrismaService,
      config as unknown as ConfigService,
      logger as unknown as AppLogger,
    );
  });

  it('sets logger context', () => {
    expect(logger.setContext).toHaveBeenCalledWith(UsersService.name);
  });

  describe('createUser', () => {
    it('throws ConflictException when email already exists', async () => {
      prisma.user.findUnique.mockResolvedValue({ id: 'exists' } as User);

      await expect(
        service.createUser({ email: 'Test@Example.Com', password: 'pw' }),
      ).rejects.toThrow(
        new ConflictException('Електронна адреса вже використовується'),
      );

      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { email: 'test@example.com' },
      });

      expect(logger.log).toHaveBeenCalled();
      expect(logger.warn).toHaveBeenCalled();
    });

    it('creates user with normalized email and hashed password', async () => {
      prisma.user.findUnique.mockResolvedValue(null);

      config.get.mockImplementation((key) =>
        key === 'BCRYPT_SALT_ROUNDS' ? '12' : undefined,
      );

      jest.spyOn(bcrypt, 'hash').mockResolvedValue('hashedPW' as never);

      const created: User = {
        id: 'u1',
        email: 'test@example.com',
        password: 'hashedPW',
        role: Role.USER,
        createdAt: new Date('2025-01-01T00:00:00.000Z'),
      };

      prisma.user.create.mockResolvedValue(created);

      const result = await service.createUser({
        email: ' Test@Example.Com ',
        password: 'pw',
      });

      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { email: 'test@example.com' },
      });
      expect(bcrypt.hash).toHaveBeenCalledWith('pw', 12);
      expect(prisma.user.create).toHaveBeenCalledWith({
        data: { email: 'test@example.com', password: 'hashedPW' },
      });
      expect(result).toEqual(created);

      expect(logger.debug).toHaveBeenCalled();
      expect(logger.log).toHaveBeenCalled();
    });

    it('uses safeRounds=10 when BCRYPT_SALT_ROUNDS is invalid', async () => {
      prisma.user.findUnique.mockResolvedValue(null);

      config.get.mockImplementation((key) =>
        key === 'BCRYPT_SALT_ROUNDS' ? 'NaN' : undefined,
      );

      jest.spyOn(bcrypt, 'hash').mockResolvedValue('hashedPW' as never);

      prisma.user.create.mockResolvedValue({
        id: 'u1',
        email: 'x@y.com',
        password: 'hashedPW',
        role: Role.USER,
        createdAt: new Date(),
      } as User);

      await service.createUser({ email: 'x@y.com', password: 'pw' });

      expect(bcrypt.hash).toHaveBeenCalledWith('pw', 10);
      expect(logger.debug).toHaveBeenCalled();
    });
  });

  describe('findByEmail', () => {
    it('normalizes email before lookup', async () => {
      prisma.user.findUnique.mockResolvedValue({ id: 'u2' } as User);

      const result = await service.findByEmail('Some@Mail.Com');

      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { email: 'some@mail.com' },
      });
      expect(result).toEqual({ id: 'u2' });

      expect(logger.debug).toHaveBeenCalled();
    });
  });

  describe('findById', () => {
    it('delegates to prisma', async () => {
      prisma.user.findUnique.mockResolvedValue({ id: 'u3' } as User);

      const res = await service.findById('u3');

      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { id: 'u3' },
      });
      expect(res).toEqual({ id: 'u3' });

      expect(logger.debug).toHaveBeenCalled();
    });
  });

  describe('updateUser', () => {
    it('updates normalized email, hashed password and role', async () => {
      config.get.mockImplementation((key) =>
        key === 'BCRYPT_SALT_ROUNDS' ? '10' : undefined,
      );

      jest.spyOn(bcrypt, 'hash').mockResolvedValue('newHash' as never);

      const updated: User = {
        id: 'u4',
        email: 'upd@mail.com',
        password: 'newHash',
        role: Role.ADMIN,
        createdAt: new Date(),
      };

      prisma.user.update.mockResolvedValue(updated);

      const res = await service.updateUser('u4', {
        email: ' Upd@Mail.Com ',
        password: 'new',
        role: Role.ADMIN,
      });

      expect(bcrypt.hash).toHaveBeenCalledWith('new', 10);
      expect(prisma.user.update).toHaveBeenCalledWith({
        where: { id: 'u4' },
        data: { email: 'upd@mail.com', password: 'newHash', role: Role.ADMIN },
      });
      expect(res).toEqual(updated);

      expect(logger.log).toHaveBeenCalled();
      expect(logger.debug).toHaveBeenCalled();
    });

    it('allows empty dto (updates with empty data object)', async () => {
      prisma.user.update.mockResolvedValue({
        id: 'u4',
        email: 'a@b.com',
        password: 'p',
        role: Role.USER,
        createdAt: new Date(),
      } as User);

      await service.updateUser('u4', {});

      expect(prisma.user.update).toHaveBeenCalledWith({
        where: { id: 'u4' },
        data: {},
      });

      expect(logger.log).toHaveBeenCalled();
    });

    it('maps P2002 error to ConflictException and logs warn', async () => {
      const err = new Prisma.PrismaClientKnownRequestError('dup', {
        code: 'P2002',
        clientVersion: 'test',
      });

      prisma.user.update.mockRejectedValue(err);

      await expect(service.updateUser('id', {})).rejects.toThrow(
        new ConflictException('Email вже використовується'),
      );

      expect(logger.warn).toHaveBeenCalled();
    });

    it('maps P2025 error to NotFoundException and logs warn', async () => {
      const err = new Prisma.PrismaClientKnownRequestError('missing', {
        code: 'P2025',
        clientVersion: 'test',
      });

      prisma.user.update.mockRejectedValue(err);

      await expect(service.updateUser('id', {})).rejects.toThrow(
        new NotFoundException('Користувача не знайдено'),
      );

      expect(logger.warn).toHaveBeenCalled();
    });

    it('logs error and rethrows unknown error', async () => {
      prisma.user.update.mockRejectedValue(new Error('boom'));

      await expect(service.updateUser('id', {})).rejects.toThrow('boom');

      expect(logger.error).toHaveBeenCalled();
    });
  });

  describe('deleteUser', () => {
    it('deletes and returns user', async () => {
      const user = { id: 'u5', email: 'x@y.com' } as User;
      prisma.user.delete.mockResolvedValue(user);

      const res = await service.deleteUser('u5');

      expect(prisma.user.delete).toHaveBeenCalledWith({
        where: { id: 'u5' },
      });
      expect(res).toEqual(user);

      expect(logger.log).toHaveBeenCalled();
    });

    it('maps P2025 error to NotFoundException and logs warn', async () => {
      const err = new Prisma.PrismaClientKnownRequestError('missing', {
        code: 'P2025',
        clientVersion: 'test',
      });

      prisma.user.delete.mockRejectedValue(err);

      await expect(service.deleteUser('u6')).rejects.toThrow(
        new NotFoundException('Користувача не знайдено'),
      );

      expect(logger.warn).toHaveBeenCalled();
    });

    it('logs error and rethrows unknown error', async () => {
      prisma.user.delete.mockRejectedValue(new Error('boom'));

      await expect(service.deleteUser('u6')).rejects.toThrow('boom');

      expect(logger.error).toHaveBeenCalled();
    });
  });

  describe('cleanup functions', () => {
    it('cleanRevokedTokens deletes tokens older than days and returns count', async () => {
      const now = new Date('2025-08-01T00:00:00.000Z');
      jest.useFakeTimers().setSystemTime(now);

      prisma.refreshToken.deleteMany.mockResolvedValue({ count: 3 });

      const count = await service.cleanRevokedTokens(5);

      const threshold = new Date(now);
      threshold.setDate(threshold.getDate() - 5);

      expect(prisma.refreshToken.deleteMany).toHaveBeenCalledWith({
        where: { revoked: true, createdAt: { lt: threshold } },
      });
      expect(count).toBe(3);

      expect(logger.log).toHaveBeenCalled();
      jest.useRealTimers();
    });

    it('cleanInactiveSessions deletes sessions older than days and returns count', async () => {
      const now = new Date('2025-08-02T00:00:00.000Z');
      jest.useFakeTimers().setSystemTime(now);

      prisma.session.deleteMany.mockResolvedValue({ count: 2 });

      const count = await service.cleanInactiveSessions(10);

      const threshold = new Date(now);
      threshold.setDate(threshold.getDate() - 10);

      expect(prisma.session.deleteMany).toHaveBeenCalledWith({
        where: { isActive: false, endedAt: { lt: threshold } },
      });
      expect(count).toBe(2);

      expect(logger.log).toHaveBeenCalled();

      jest.useRealTimers();
    });
  });
});
