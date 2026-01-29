/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */

import { AuthMaintenanceService } from './auth-maintenance.service';
import type { PrismaService } from 'src/prisma/prisma.service';
import type { AppLogger } from 'src/logger/logger.service';

type PrismaMock = {
  refreshToken: {
    deleteMany: jest.Mock<Promise<{ count: number }>, [args: any]>;
  };
  session: { deleteMany: jest.Mock<Promise<{ count: number }>, [args: any]> };
};

type LoggerMock = jest.Mocked<Pick<AppLogger, 'setContext' | 'log'>>;

describe('AuthMaintenanceService', () => {
  let service: AuthMaintenanceService;
  let prisma: PrismaMock;
  let logger: LoggerMock;

  beforeEach(() => {
    jest.clearAllMocks();

    prisma = {
      refreshToken: { deleteMany: jest.fn() },
      session: { deleteMany: jest.fn() },
    };

    logger = {
      setContext: jest.fn(),
      log: jest.fn(),
    };

    service = new AuthMaintenanceService(
      prisma as unknown as PrismaService,
      logger as unknown as AppLogger,
    );
  });

  it('sets logger context in constructor', () => {
    expect(logger.setContext).toHaveBeenCalledWith(AuthMaintenanceService.name);
  });

  it('cleanRevokedTokens deletes tokens older than days and returns count', async () => {
    const now = new Date('2025-08-01T00:00:00.000Z');
    jest.useFakeTimers().setSystemTime(now);

    prisma.refreshToken.deleteMany.mockResolvedValue({ count: 3 });

    const count = await service.cleanRevokedTokens(10);

    expect(prisma.refreshToken.deleteMany).toHaveBeenCalledWith({
      where: {
        revoked: true,
        createdAt: { lt: new Date('2025-07-22T00:00:00.000Z') },
      },
    });
    expect(count).toBe(3);

    jest.useRealTimers();
  });

  it('cleanInactiveSessions deletes sessions older than days and returns count', async () => {
    const now = new Date('2025-08-01T00:00:00.000Z');
    jest.useFakeTimers().setSystemTime(now);

    prisma.session.deleteMany.mockResolvedValue({ count: 5 });

    const count = await service.cleanInactiveSessions(7);

    expect(prisma.session.deleteMany).toHaveBeenCalledWith({
      where: {
        isActive: false,
        endedAt: { lt: new Date('2025-07-25T00:00:00.000Z') },
      },
    });
    expect(count).toBe(5);

    jest.useRealTimers();
  });
});
