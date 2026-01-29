/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */

import { SessionService } from './session.service';
import type { PrismaService } from 'src/prisma/prisma.service';
import type { AppLogger } from 'src/logger/logger.service';

jest.mock('src/common/helpers/ip-normalize', () => ({
  normalizeIp: jest.fn(),
}));
import { normalizeIp } from 'src/common/helpers/ip-normalize';

jest.mock('src/common/helpers/log-sanitize', () => ({
  maskIp: jest.fn(),
  hashId: jest.fn(),
}));
import { maskIp, hashId } from 'src/common/helpers/log-sanitize';

type PrismaSessionModel = {
  create: jest.Mock<Promise<{ id: string }>, [args: any]>;
  findMany: jest.Mock<Promise<any[]>, [args: any]>;
  updateMany: jest.Mock<Promise<{ count: number }>, [args: any]>;
  count: jest.Mock<Promise<number>, [args: any]>;
};

type PrismaRefreshTokenModel = {
  updateMany: jest.Mock<Promise<{ count: number }>, [args: any]>;
};

type PrismaMock = {
  session: PrismaSessionModel;
  refreshToken: PrismaRefreshTokenModel;
  $transaction: jest.Mock;
};

type LoggerMock = jest.Mocked<Pick<AppLogger, 'setContext' | 'log' | 'debug'>>;

describe('SessionService', () => {
  let service: SessionService;

  let prisma: PrismaMock;
  let logger: LoggerMock;

  beforeEach(() => {
    jest.clearAllMocks();

    prisma = {
      session: {
        create: jest.fn(),
        findMany: jest.fn(),
        updateMany: jest.fn(),
        count: jest.fn(),
      },
      refreshToken: {
        updateMany: jest.fn(),
      },
      $transaction: jest.fn(),
    };

    prisma.$transaction.mockImplementation(async (cb: any) => {
      const tx = {
        session: prisma.session,
        refreshToken: prisma.refreshToken,
      };
      // eslint-disable-next-line @typescript-eslint/no-unsafe-return
      return await cb(tx);
    });

    logger = {
      setContext: jest.fn(),
      log: jest.fn(),
      debug: jest.fn(),
    };

    service = new SessionService(
      prisma as unknown as PrismaService,
      logger as unknown as AppLogger,
    );
  });

  it('sets logger context in constructor', () => {
    expect(logger.setContext).toHaveBeenCalledWith(SessionService.name);
  });

  describe('create', () => {
    it('stores normalized ip and trimmed userAgent; logs sanitized meta', async () => {
      (normalizeIp as jest.Mock).mockReturnValue('1.1.1.1');
      (maskIp as jest.Mock).mockReturnValue('1.1.*.*');
      (hashId as jest.Mock).mockReturnValue('ua_hash');

      prisma.session.create.mockResolvedValue({ id: 'sid-1' });

      const result = await service.create(
        'sid-1',
        'u1',
        'jti-1',
        ' 1.1.1.1 ',
        ' UA ',
      );

      expect(normalizeIp).toHaveBeenCalledWith(' 1.1.1.1 ');

      expect(prisma.session.create).toHaveBeenCalledWith({
        data: {
          id: 'sid-1',
          userId: 'u1',
          refreshTokenId: 'jti-1',
          ip: '1.1.1.1',
          userAgent: 'UA',
        },
      });

      expect(logger.log).toHaveBeenCalledWith(
        'Session created',
        SessionService.name,
        {
          event: 'session.created',
          userId: 'u1',
          sid: 'sid-1',
          jti: 'jti-1',
          ipMasked: '1.1.*.*',
          uaHash: 'ua_hash',
        },
      );

      expect(maskIp).toHaveBeenCalledWith('1.1.1.1');
      expect(hashId).toHaveBeenCalledWith('UA');

      expect(result).toEqual({ id: 'sid-1' });
    });

    it('handles missing ip/userAgent (stores nulls) and logs without ipMasked/uaHash', async () => {
      prisma.session.create.mockResolvedValue({ id: 'sid-2' });

      const result = await service.create('sid-2', 'u2', 'jti-2');

      expect(prisma.session.create).toHaveBeenCalledWith({
        data: {
          id: 'sid-2',
          userId: 'u2',
          refreshTokenId: 'jti-2',
          ip: null,
          userAgent: null,
        },
      });

      expect(logger.log).toHaveBeenCalledWith(
        'Session created',
        SessionService.name,
        {
          event: 'session.created',
          userId: 'u2',
          sid: 'sid-2',
          jti: 'jti-2',
          ipMasked: undefined,
          uaHash: undefined,
        },
      );

      expect(maskIp).not.toHaveBeenCalled();
      expect(hashId).not.toHaveBeenCalled();

      expect(result).toEqual({ id: 'sid-2' });
    });
  });

  describe('getUserSessions', () => {
    it('delegates to prisma.session.findMany', async () => {
      prisma.session.findMany.mockResolvedValue([]);

      await service.getUserSessions('u1');

      expect(prisma.session.findMany).toHaveBeenCalledWith({
        where: { userId: 'u1' },
      });
    });
  });

  describe('getActiveUserSessions', () => {
    it('uses default take=50 and sorts by startedAt desc', async () => {
      prisma.session.findMany.mockResolvedValue([]);

      await service.getActiveUserSessions('u1');

      expect(prisma.session.findMany).toHaveBeenCalledWith({
        where: { userId: 'u1', isActive: true },
        orderBy: { startedAt: 'desc' },
        take: 50,
      });
    });

    it('respects custom take', async () => {
      prisma.session.findMany.mockResolvedValue([]);

      await service.getActiveUserSessions('u1', 10);

      expect(prisma.session.findMany).toHaveBeenCalledWith({
        where: { userId: 'u1', isActive: true },
        orderBy: { startedAt: 'desc' },
        take: 10,
      });
    });
  });

  describe('getAllUserSessions', () => {
    it('returns all sessions sorted desc', async () => {
      prisma.session.findMany.mockResolvedValue([]);

      await service.getAllUserSessions('u3');

      expect(prisma.session.findMany).toHaveBeenCalledWith({
        where: { userId: 'u3' },
        orderBy: { startedAt: 'desc' },
      });
    });
  });

  describe('termination operations', () => {
    beforeEach(() => {
      prisma.session.updateMany.mockResolvedValue({ count: 1 });
      prisma.refreshToken.updateMany.mockResolvedValue({ count: 1 });

      prisma.session.findMany.mockResolvedValue([
        { id: 'sid-any', refreshTokenId: 'jti-any' },
      ]);
    });

    it('terminateSpecificSession normalizes ip and trims userAgent; terminates by ids in transaction', async () => {
      (normalizeIp as jest.Mock).mockReturnValue('2.2.2.2');
      (maskIp as jest.Mock).mockReturnValue('2.2.*.*');
      (hashId as jest.Mock).mockReturnValue('ua_hash');

      const fixed = new Date('2025-07-01T00:00:00.000Z');
      jest.useFakeTimers().setSystemTime(fixed);

      await service.terminateSpecificSession('u4', ' 2.2.2.2 ', ' UA ');

      expect(prisma.session.findMany).toHaveBeenCalledWith({
        where: {
          userId: 'u4',
          ip: '2.2.2.2',
          userAgent: 'UA',
          isActive: true,
        },
        select: { id: true, refreshTokenId: true },
      });

      expect(prisma.$transaction).toHaveBeenCalled();

      expect(prisma.session.updateMany).toHaveBeenCalledWith({
        where: {
          id: { in: ['sid-any'] },
          isActive: true,
        },
        data: {
          isActive: false,
          endedAt: new Date(fixed.getTime()),
        },
      });

      jest.useRealTimers();
    });

    it('terminateOtherSessions selects by NOT id, then terminates by ids in transaction', async () => {
      const now = new Date('2025-07-02T00:00:00.000Z');
      jest.useFakeTimers().setSystemTime(now);

      await service.terminateOtherSessions('u5', 'sid123');

      expect(prisma.session.findMany).toHaveBeenCalledWith({
        where: {
          userId: 'u5',
          NOT: { id: 'sid123' },
          isActive: true,
        },
        select: { id: true, refreshTokenId: true },
      });

      expect(prisma.$transaction).toHaveBeenCalled();

      expect(prisma.session.updateMany).toHaveBeenCalledWith({
        where: {
          id: { in: ['sid-any'] },
          isActive: true,
        },
        data: {
          isActive: false,
          endedAt: new Date(now.getTime()),
        },
      });

      jest.useRealTimers();
    });

    it('terminateAll selects by userId, then terminates by ids in transaction', async () => {
      const now = new Date('2025-07-03T00:00:00.000Z');
      jest.useFakeTimers().setSystemTime(now);

      await service.terminateAll('u6');

      expect(prisma.session.findMany).toHaveBeenCalledWith({
        where: { userId: 'u6', isActive: true },
        select: { id: true, refreshTokenId: true },
      });

      expect(prisma.$transaction).toHaveBeenCalled();

      expect(prisma.session.updateMany).toHaveBeenCalledWith({
        where: {
          id: { in: ['sid-any'] },
          isActive: true,
        },
        data: {
          isActive: false,
          endedAt: new Date(now.getTime()),
        },
      });

      jest.useRealTimers();
    });

    it('terminateByRefreshToken selects by refreshTokenId, then terminates by ids in transaction', async () => {
      const now = new Date('2025-07-04T00:00:00.000Z');
      jest.useFakeTimers().setSystemTime(now);

      await service.terminateByRefreshToken('jti-77');

      expect(prisma.session.findMany).toHaveBeenCalledWith({
        where: { refreshTokenId: 'jti-77', isActive: true },
        select: { id: true, refreshTokenId: true },
      });

      expect(prisma.$transaction).toHaveBeenCalled();

      expect(prisma.session.updateMany).toHaveBeenCalledWith({
        where: {
          id: { in: ['sid-any'] },
          isActive: true,
        },
        data: {
          isActive: false,
          endedAt: new Date(now.getTime()),
        },
      });

      jest.useRealTimers();
    });

    it('logs debug noop when nothing terminated (no sessions)', async () => {
      prisma.session.findMany.mockResolvedValue([]);

      await service.terminateAll('u6');

      expect(prisma.$transaction).not.toHaveBeenCalled();

      expect(logger.debug).toHaveBeenCalledWith(
        'Terminate sessions: nothing to terminate',
        SessionService.name,
        expect.objectContaining({
          event: 'session.terminate.noop',
          userId: 'u6',
          reason: 'all',
        }),
      );
    });
  });

  describe('countActive', () => {
    it('counts active sessions', async () => {
      prisma.session.count.mockResolvedValue(5);

      const result = await service.countActive('u7');

      expect(prisma.session.count).toHaveBeenCalledWith({
        where: { userId: 'u7', isActive: true },
      });
      expect(result).toBe(5);
    });
  });
});
