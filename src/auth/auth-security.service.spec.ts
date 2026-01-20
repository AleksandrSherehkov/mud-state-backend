/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */

import { UnauthorizedException } from '@nestjs/common';
import { AuthSecurityService } from './auth-security.service';
import type { PrismaService } from 'src/prisma/prisma.service';
import type { ConfigService } from '@nestjs/config';
import type { AppLogger } from 'src/logger/logger.service';

jest.mock('src/common/helpers/log-sanitize', () => ({
  hashId: jest.fn(() => 'ua-hash'),
  maskIp: jest.fn(() => 'ip-masked'),
}));

describe('AuthSecurityService', () => {
  let service: AuthSecurityService;

  let prisma: {
    userSecurity: {
      findUnique: jest.Mock;
      upsert: jest.Mock;
    };
  };

  let config: {
    get: jest.Mock;
  };

  let logger: jest.Mocked<
    Pick<
      AppLogger,
      'setContext' | 'warn' | 'debug' | 'log' | 'error' | 'verbose' | 'silly'
    >
  >;

  beforeEach(() => {
    jest.clearAllMocks();

    prisma = {
      userSecurity: {
        findUnique: jest.fn(),
        upsert: jest.fn(),
      },
    };

    config = {
      get: jest.fn((k: string) => {
        const map: Record<string, unknown> = {
          AUTH_LOCK_MAX_ATTEMPTS: 3,
          AUTH_LOCK_BASE_SECONDS: 2,
          AUTH_LOCK_MAX_SECONDS: 300,
          AUTH_LOCK_WINDOW_SECONDS: 900,
        };
        return map[k];
      }),
    };

    logger = {
      setContext: jest.fn(),
      warn: jest.fn(),
      debug: jest.fn(),
      log: jest.fn(),
      error: jest.fn(),
      verbose: jest.fn(),
      silly: jest.fn(),
    };

    service = new AuthSecurityService(
      prisma as unknown as PrismaService,
      config as unknown as ConfigService,
      logger as unknown as AppLogger,
    );

    expect(logger.setContext).toHaveBeenCalledWith('AuthSecurityService');
  });

  describe('assertNotLocked', () => {
    it('does nothing when no security row', async () => {
      prisma.userSecurity.findUnique.mockResolvedValue(null);

      await expect(service.assertNotLocked('u1')).resolves.toBeUndefined();
      expect(prisma.userSecurity.findUnique).toHaveBeenCalledWith({
        where: { userId: 'u1' },
      });
    });

    it('does nothing when lockedUntil is null', async () => {
      prisma.userSecurity.findUnique.mockResolvedValue({
        userId: 'u1',
        lockedUntil: null,
      });

      await expect(service.assertNotLocked('u1')).resolves.toBeUndefined();
    });

    it('throws Unauthorized when lockedUntil in the future', async () => {
      const future = new Date(Date.now() + 60_000);
      prisma.userSecurity.findUnique.mockResolvedValue({
        userId: 'u1',
        lockedUntil: future,
      });

      await expect(service.assertNotLocked('u1')).rejects.toThrow(
        new UnauthorizedException('Невірний email або пароль'),
      );

      expect(logger.warn).toHaveBeenCalled();
    });

    it('does nothing when lockedUntil in the past', async () => {
      const past = new Date(Date.now() - 60_000);
      prisma.userSecurity.findUnique.mockResolvedValue({
        userId: 'u1',
        lockedUntil: past,
      });

      await expect(service.assertNotLocked('u1')).resolves.toBeUndefined();
    });
  });

  describe('onLoginFailed', () => {
    it('sets count=1 when window expired', async () => {
      const now = new Date('2026-01-20T00:00:00.000Z');
      jest.useFakeTimers().setSystemTime(now);

      prisma.userSecurity.findUnique.mockResolvedValue({
        failedLoginCount: 7,
        lastFailedAt: new Date('2026-01-19T00:00:00.000Z'), // давно -> окно истекло
        lockedUntil: null,
      });

      prisma.userSecurity.upsert.mockResolvedValue(undefined);

      await expect(
        service.onLoginFailed({ userId: 'u1', ip: '1.1.1.1', userAgent: 'UA' }),
      ).rejects.toThrow(new UnauthorizedException('Невірний email або пароль'));

      expect(prisma.userSecurity.upsert).toHaveBeenCalled();

      const args = prisma.userSecurity.upsert.mock.calls[0][0];
      expect(args.where).toEqual({ userId: 'u1' });
      expect(args.update.failedLoginCount).toBe(1);
      expect(args.update.lockedUntil).toBeNull();

      jest.useRealTimers();
    });

    it('increments count when window NOT expired', async () => {
      const now = new Date('2026-01-20T00:00:00.000Z');
      jest.useFakeTimers().setSystemTime(now);

      prisma.userSecurity.findUnique.mockResolvedValue({
        failedLoginCount: 1,
        lastFailedAt: new Date('2026-01-19T23:59:30.000Z'), // 30s ago -> внутри окна
        lockedUntil: null,
      });

      prisma.userSecurity.upsert.mockResolvedValue(undefined);

      await expect(
        service.onLoginFailed({ userId: 'u1', ip: null, userAgent: null }),
      ).rejects.toThrow(new UnauthorizedException('Невірний email або пароль'));

      const args = prisma.userSecurity.upsert.mock.calls[0][0];
      expect(args.update.failedLoginCount).toBe(2);
      expect(args.update.lockedUntil).toBeNull();

      jest.useRealTimers();
    });

    it('locks account when attempt >= maxAttempts', async () => {
      // maxAttempts=3, baseSec=2
      const now = new Date('2026-01-20T00:00:00.000Z');
      jest.useFakeTimers().setSystemTime(now);

      prisma.userSecurity.findUnique.mockResolvedValue({
        failedLoginCount: 2,
        lastFailedAt: new Date('2026-01-19T23:59:50.000Z'),
        lockedUntil: null,
      });

      prisma.userSecurity.upsert.mockResolvedValue(undefined);

      await expect(
        service.onLoginFailed({ userId: 'u1', ip: '2.2.2.2', userAgent: 'UA' }),
      ).rejects.toThrow(new UnauthorizedException('Невірний email або пароль'));

      const args = prisma.userSecurity.upsert.mock.calls[0][0];

      // nextCount = 3 -> attempt=3 -> delaySec=2*2^(3-1)=8
      expect(args.update.failedLoginCount).toBe(3);
      expect(args.update.lockedUntil).toBeInstanceOf(Date);

      const lockedUntil: Date = args.update.lockedUntil;
      expect(lockedUntil.getTime()).toBe(now.getTime() + 8_000);

      expect(logger.warn).toHaveBeenCalled(); // lock set warn

      jest.useRealTimers();
    });
  });

  describe('onLoginSuccess', () => {
    it('resets counters via upsert', async () => {
      prisma.userSecurity.upsert.mockResolvedValue(undefined);

      await expect(service.onLoginSuccess('u1')).resolves.toBeUndefined();

      expect(prisma.userSecurity.upsert).toHaveBeenCalledWith({
        where: { userId: 'u1' },
        create: {
          userId: 'u1',
          failedLoginCount: 0,
          lockedUntil: null,
          lastFailedAt: null,
        },
        update: { failedLoginCount: 0, lockedUntil: null, lastFailedAt: null },
      });

      expect(logger.debug).toHaveBeenCalled();
    });
  });
});
