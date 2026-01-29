jest.mock('cron', () => ({
  CronJob: jest
    .fn<
      { start: jest.Mock<void, []>; stop: jest.Mock<void, []> },
      [string, () => void]
    >()
    .mockImplementation(() => ({
      start: jest.fn<void, []>(),
      stop: jest.fn<void, []>(),
    })),
}));

import { TokenCleanupJob } from './token-cleanup.job';
import type { ConfigService } from '@nestjs/config';
import type { AppLogger } from 'src/logger/logger.service';
import type { SchedulerRegistry } from '@nestjs/schedule';
import type { AuthMaintenanceService } from 'src/auth/auth-maintenance.service';

type CronJobLike = { stop: jest.Mock<void, []> };

describe('TokenCleanupJob', () => {
  let maintenance: {
    cleanRevokedTokens: jest.Mock<Promise<number>, [olderThanDays?: number]>;
    cleanInactiveSessions: jest.Mock<Promise<number>, [olderThanDays?: number]>;
  };

  let config: {
    get: jest.Mock<unknown, [key: string, defaultValue?: unknown]>;
  };

  let logger: jest.Mocked<
    Pick<AppLogger, 'setContext' | 'log' | 'error' | 'debug'>
  >;

  let schedulerRegistry: {
    addCronJob: jest.Mock<void, [name: string, job: unknown]>;
    getCronJob: jest.Mock<CronJobLike, [name: string]>;
    deleteCronJob: jest.Mock<void, [name: string]>;
  };

  let job: TokenCleanupJob;

  beforeEach(() => {
    jest.clearAllMocks();

    maintenance = {
      cleanRevokedTokens: jest.fn<Promise<number>, [olderThanDays?: number]>(),
      cleanInactiveSessions: jest.fn<
        Promise<number>,
        [olderThanDays?: number]
      >(),
    };

    config = {
      get: jest.fn<unknown, [key: string, defaultValue?: unknown]>(),
    };

    logger = {
      setContext: jest.fn(),
      log: jest.fn(),
      error: jest.fn(),
      debug: jest.fn(),
    };

    schedulerRegistry = {
      addCronJob: jest.fn<void, [name: string, job: unknown]>(),
      getCronJob: jest.fn<CronJobLike, [name: string]>().mockReturnValue({
        stop: jest.fn<void, []>(),
      }),
      deleteCronJob: jest.fn<void, [name: string]>(),
    };

    // ✅ порядок аргументов как в реальном конструкторе:
    // (config, schedulerRegistry, logger, maintenance)
    job = new TokenCleanupJob(
      config as unknown as ConfigService,
      schedulerRegistry as unknown as SchedulerRegistry,
      logger as unknown as AppLogger,
      maintenance as unknown as AuthMaintenanceService,
    );
  });

  afterEach(() => {
    job.onModuleDestroy();
  });

  it('sets logger context on construction', () => {
    expect(logger.setContext).toHaveBeenCalledWith(TokenCleanupJob.name);
  });

  it('registers cron job on module init with cron from config', () => {
    config.get.mockImplementation((key: string, def?: unknown) => {
      if (key === 'TOKEN_CLEANUP_CRON') return '*/1 * * * *';
      if (key === 'TOKEN_CLEANUP_DAYS') return 7;
      return def;
    });

    job.onModuleInit();

    expect(schedulerRegistry.addCronJob).toHaveBeenCalledWith(
      'token-cleanup-job',
      expect.anything(),
    );

    expect(logger.debug).toHaveBeenCalledWith(
      'Token cleanup job registered',
      TokenCleanupJob.name,
      expect.objectContaining({
        event: 'cleanup.init',
        cron: '*/1 * * * *',
        days: 7,
      }),
    );
  });

  it('stops and deletes cron job on module destroy', () => {
    job.onModuleDestroy();

    expect(schedulerRegistry.getCronJob).toHaveBeenCalledWith(
      'token-cleanup-job',
    );
    expect(schedulerRegistry.deleteCronJob).toHaveBeenCalledWith(
      'token-cleanup-job',
    );
  });

  it('uses TOKEN_CLEANUP_DAYS from config (default=7)', async () => {
    config.get.mockImplementation((key: string, def?: unknown) => {
      if (key === 'TOKEN_CLEANUP_DAYS') return 7;
      return def;
    });

    maintenance.cleanRevokedTokens.mockResolvedValue(0);
    maintenance.cleanInactiveSessions.mockResolvedValue(0);

    await job.handleCleanup();

    expect(config.get).toHaveBeenCalledWith('TOKEN_CLEANUP_DAYS', 7);
    expect(maintenance.cleanRevokedTokens).toHaveBeenCalledWith(7);
    expect(maintenance.cleanInactiveSessions).toHaveBeenCalledWith(7);

    expect(logger.debug).toHaveBeenCalledWith(
      'Token cleanup start',
      TokenCleanupJob.name,
      { event: 'cleanup.start', days: 7 },
    );

    expect(logger.debug).toHaveBeenCalledWith(
      'Token cleanup finished',
      TokenCleanupJob.name,
      { event: 'cleanup.done', days: 7, deletedTokens: 0, deletedSessions: 0 },
    );

    expect(logger.debug).toHaveBeenCalledWith(
      'Token cleanup noop',
      TokenCleanupJob.name,
      { event: 'cleanup.noop', days: 7 },
    );
  });

  it('logs deleted when counts are positive', async () => {
    config.get.mockImplementation((key: string, def?: unknown) => {
      if (key === 'TOKEN_CLEANUP_DAYS') return 5;
      return def;
    });

    maintenance.cleanRevokedTokens.mockResolvedValue(2);
    maintenance.cleanInactiveSessions.mockResolvedValue(3);

    await job.handleCleanup();

    expect(logger.debug).toHaveBeenCalledWith(
      'Token cleanup finished',
      TokenCleanupJob.name,
      {
        event: 'cleanup.done',
        days: 5,
        deletedTokens: 2,
        deletedSessions: 3,
      },
    );

    expect(logger.log).toHaveBeenCalledWith(
      'Token cleanup deleted records',
      TokenCleanupJob.name,
      {
        event: 'cleanup.deleted',
        days: 5,
        deletedTokens: 2,
        deletedSessions: 3,
      },
    );
  });

  it('logs error when cleanup fails (Error)', async () => {
    config.get.mockImplementation((key: string, def?: unknown) => {
      if (key === 'TOKEN_CLEANUP_DAYS') return 7;
      return def;
    });

    const error = new Error('failure');
    maintenance.cleanRevokedTokens.mockRejectedValue(error);
    maintenance.cleanInactiveSessions.mockResolvedValue(1);

    await job.handleCleanup();

    expect(logger.error).toHaveBeenCalledWith(
      'Token cleanup failed',
      error.stack,
      TokenCleanupJob.name,
      expect.objectContaining({
        event: 'cleanup.fail',
        days: 7,
        errorName: 'Error',
        errorMessage: 'failure',
      }),
    );
  });

  it('logs error when cleanup fails (non-Error)', async () => {
    config.get.mockImplementation((key: string, def?: unknown) => {
      if (key === 'TOKEN_CLEANUP_DAYS') return 7;
      return def;
    });

    maintenance.cleanRevokedTokens.mockRejectedValue('boom');
    maintenance.cleanInactiveSessions.mockResolvedValue(1);

    await job.handleCleanup();

    expect(logger.error).toHaveBeenCalledWith(
      'Token cleanup failed',
      undefined,
      TokenCleanupJob.name,
      expect.objectContaining({
        event: 'cleanup.fail',
        days: 7,
        errorName: 'UnknownError',
        errorMessage: 'boom',
      }),
    );
  });
});
