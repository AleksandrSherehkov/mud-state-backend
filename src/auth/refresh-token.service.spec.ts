import { UnauthorizedException } from '@nestjs/common';

import { RefreshTokenService } from './refresh-token.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { AppLogger } from 'src/logger/logger.service';

jest.mock('src/common/helpers/log-sanitize', () => ({
  maskIp: jest.fn((ip: string) => ip),
  hashId: jest.fn(() => 'ua-hash'),
}));

describe('RefreshTokenService', () => {
  type PrismaMock = {
    refreshToken: {
      create: jest.Mock;
      findMany: jest.Mock;
      updateMany: jest.Mock;
      update: jest.Mock;
      findUnique: jest.Mock;
      findFirst: jest.Mock;
      count: jest.Mock;
    };
  };

  let prisma: PrismaMock;
  let service: RefreshTokenService;

  let logger: jest.Mocked<
    Pick<
      AppLogger,
      'setContext' | 'log' | 'warn' | 'error' | 'debug' | 'verbose' | 'silly'
    >
  >;

  beforeEach(() => {
    prisma = {
      refreshToken: {
        create: jest.fn(),
        findMany: jest.fn(),
        updateMany: jest.fn(),
        update: jest.fn(),
        findUnique: jest.fn(),
        findFirst: jest.fn(),
        count: jest.fn(),
      },
    };

    logger = {
      setContext: jest.fn(),
      log: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
      debug: jest.fn(),
      verbose: jest.fn(),
      silly: jest.fn(),
    };

    service = new RefreshTokenService(
      prisma as unknown as PrismaService,
      logger as unknown as AppLogger,
    );

    expect(logger.setContext).toHaveBeenCalledWith('RefreshTokenService');
  });

  describe('create', () => {
    it('creates refresh token with provided params', async () => {
      prisma.refreshToken.create.mockResolvedValue({ id: 't1', userId: 'u1' });

      await service.create('u1', 'jti1', 'hash1', 'ip', 'ua');

      expect(prisma.refreshToken.create).toHaveBeenCalledWith({
        data: {
          userId: 'u1',
          jti: 'jti1',
          tokenHash: 'hash1',
          ip: 'ip',
          userAgent: 'ua',
        },
      });

      expect(logger.log).toHaveBeenCalled();
    });

    it('allows optional ip/userAgent', async () => {
      prisma.refreshToken.create.mockResolvedValue({ id: 't2', userId: 'u2' });

      await service.create('u2', 'jti2', 'hash2');

      expect(prisma.refreshToken.create).toHaveBeenCalledWith({
        data: {
          userId: 'u2',
          jti: 'jti2',
          tokenHash: 'hash2',
          ip: undefined,
          userAgent: undefined,
        },
      });

      expect(logger.log).toHaveBeenCalled();
    });
  });

  describe('getActiveTokens', () => {
    it('queries active tokens ordered desc with default take=50', async () => {
      prisma.refreshToken.findMany.mockResolvedValue([]);

      await service.getActiveTokens('u3');

      expect(prisma.refreshToken.findMany).toHaveBeenCalledWith({
        where: { userId: 'u3', revoked: false },
        orderBy: { createdAt: 'desc' },
        take: 50,
      });
    });

    it('uses custom take', async () => {
      prisma.refreshToken.findMany.mockResolvedValue([]);

      await service.getActiveTokens('u4', 5);

      expect(prisma.refreshToken.findMany).toHaveBeenCalledWith({
        where: { userId: 'u4', revoked: false },
        orderBy: { createdAt: 'desc' },
        take: 5,
      });
    });
  });

  describe('revokeAll', () => {
    it('revokes all active tokens for user', async () => {
      prisma.refreshToken.updateMany.mockResolvedValue({ count: 2 });

      await service.revokeAll('u5');

      expect(prisma.refreshToken.updateMany).toHaveBeenCalledWith({
        where: { userId: 'u5', revoked: false },
        data: { revoked: true },
      });

      expect(logger.log).toHaveBeenCalled();
    });

    it('logs noop when nothing revoked', async () => {
      prisma.refreshToken.updateMany.mockResolvedValue({ count: 0 });

      await service.revokeAll('u5');

      expect(logger.debug).toHaveBeenCalled();
    });
  });

  describe('revokeByJti', () => {
    it('revokes token by jti', async () => {
      prisma.refreshToken.update.mockResolvedValue({ id: 't', userId: 'u1' });

      await service.revokeByJti('jti3');

      expect(prisma.refreshToken.update).toHaveBeenCalledWith({
        where: { jti: 'jti3' },
        data: { revoked: true },
      });

      expect(logger.log).toHaveBeenCalled();
    });
  });

  describe('revokeIfActiveByHash', () => {
    it('claims only active token for user+hash (count=1) and logs success', async () => {
      prisma.refreshToken.updateMany.mockResolvedValue({ count: 1 });

      await service.revokeIfActiveByHash('jti4', 'u6', 'hash-4');

      expect(prisma.refreshToken.updateMany).toHaveBeenCalledWith({
        where: {
          jti: 'jti4',
          userId: 'u6',
          tokenHash: 'hash-4',
          revoked: false,
        },
        data: { revoked: true },
      });

      expect(logger.log).toHaveBeenCalled();
    });

    it('logs warn when claim failed (count=0)', async () => {
      prisma.refreshToken.updateMany.mockResolvedValue({ count: 0 });

      await service.revokeIfActiveByHash('jti4', 'u6', 'hash-4');

      expect(logger.warn).toHaveBeenCalled();
    });
  });

  describe('validate', () => {
    it('throws if token not found', async () => {
      prisma.refreshToken.findUnique.mockResolvedValue(null);

      await expect(service.validate('j1', 'u7')).rejects.toThrow(
        new UnauthorizedException('Токен відкликано або недійсний'),
      );

      expect(prisma.refreshToken.findUnique).toHaveBeenCalledWith({
        where: { jti: 'j1' },
      });
      expect(logger.warn).toHaveBeenCalled();
    });

    it('throws if token revoked', async () => {
      prisma.refreshToken.findUnique.mockResolvedValue({
        revoked: true,
        userId: 'u7',
      });

      await expect(service.validate('j2', 'u7')).rejects.toThrow(
        new UnauthorizedException('Токен відкликано або недійсний'),
      );

      expect(logger.warn).toHaveBeenCalled();
    });

    it('throws if user mismatch', async () => {
      prisma.refreshToken.findUnique.mockResolvedValue({
        revoked: false,
        userId: 'other',
      });

      await expect(service.validate('j3', 'u7')).rejects.toThrow(
        new UnauthorizedException('Токен відкликано або недійсний'),
      );

      expect(logger.warn).toHaveBeenCalled();
    });

    it('resolves when token is valid', async () => {
      prisma.refreshToken.findUnique.mockResolvedValue({
        revoked: false,
        userId: 'u8',
      });

      await expect(service.validate('j4', 'u8')).resolves.toBeUndefined();
    });
  });

  describe('findValid', () => {
    it('finds first valid (not revoked) token for user and jti', async () => {
      prisma.refreshToken.findFirst.mockResolvedValue({ id: 't3' });

      await service.findValid('u9', 'j9');

      expect(prisma.refreshToken.findFirst).toHaveBeenCalledWith({
        where: { userId: 'u9', jti: 'j9', revoked: false },
      });
    });
  });

  describe('countActive', () => {
    it('counts active (not revoked) tokens', async () => {
      prisma.refreshToken.count.mockResolvedValue(7);

      const result = await service.countActive('u10');

      expect(prisma.refreshToken.count).toHaveBeenCalledWith({
        where: { userId: 'u10', revoked: false },
      });
      expect(result).toBe(7);
    });
  });
});
