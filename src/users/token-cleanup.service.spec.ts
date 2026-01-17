import { TokenCleanupService } from './token-cleanup.service';
import type { UsersService } from '../users/users.service';
import type { ConfigService } from '@nestjs/config';
import type { AppLogger } from 'src/logger/logger.service';

describe('TokenCleanupService', () => {
  let usersService: {
    cleanRevokedTokens: jest.Mock<Promise<number>, [olderThanDays?: number]>;
    cleanInactiveSessions: jest.Mock<Promise<number>, [olderThanDays?: number]>;
  };

  let config: {
    get: jest.Mock<number, [key: string, defaultValue: number]>;
  };

  let logger: jest.Mocked<
    Pick<AppLogger, 'setContext' | 'log' | 'error' | 'debug'>
  >;

  let service: TokenCleanupService;

  beforeEach(() => {
    jest.clearAllMocks();

    usersService = {
      cleanRevokedTokens: jest.fn<Promise<number>, [olderThanDays?: number]>(),
      cleanInactiveSessions: jest.fn<
        Promise<number>,
        [olderThanDays?: number]
      >(),
    };

    config = {
      get: jest.fn<number, [key: string, defaultValue: number]>(),
    };

    logger = {
      setContext: jest.fn(),
      log: jest.fn(),
      error: jest.fn(),
      debug: jest.fn(),
    };

    service = new TokenCleanupService(
      usersService as unknown as UsersService,
      config as unknown as ConfigService,
      logger as unknown as AppLogger,
    );
  });

  it('sets logger context on construction', () => {
    expect(logger.setContext).toHaveBeenCalledWith(TokenCleanupService.name);
  });

  it('uses TOKEN_CLEANUP_DAYS from config (default=7)', async () => {
    config.get.mockReturnValue(7);
    usersService.cleanRevokedTokens.mockResolvedValue(0);
    usersService.cleanInactiveSessions.mockResolvedValue(0);

    await service.handleCleanup();

    expect(config.get).toHaveBeenCalledWith('TOKEN_CLEANUP_DAYS', 7);
    expect(usersService.cleanRevokedTokens).toHaveBeenCalledWith(7);
    expect(usersService.cleanInactiveSessions).toHaveBeenCalledWith(7);

    expect(logger.debug).toHaveBeenCalledWith(
      'Token cleanup start',
      TokenCleanupService.name,
      { event: 'cleanup.start', days: 7 },
    );

    expect(logger.debug).toHaveBeenCalledWith(
      'Token cleanup finished',
      TokenCleanupService.name,
      { event: 'cleanup.done', days: 7, deletedTokens: 0, deletedSessions: 0 },
    );

    expect(logger.debug).toHaveBeenCalledWith(
      'Token cleanup noop',
      TokenCleanupService.name,
      {
        event: 'cleanup.noop',
        days: 7,
      },
    );
  });

  it('logs finished with counts when counts are positive', async () => {
    config.get.mockReturnValue(5);
    usersService.cleanRevokedTokens.mockResolvedValue(2);
    usersService.cleanInactiveSessions.mockResolvedValue(3);

    await service.handleCleanup();

    expect(logger.debug).toHaveBeenCalledWith(
      'Token cleanup finished',
      TokenCleanupService.name,
      {
        event: 'cleanup.done',
        days: 5,
        deletedTokens: 2,
        deletedSessions: 3,
      },
    );

    expect(logger.log).toHaveBeenCalledWith(
      'Token cleanup deleted records',
      TokenCleanupService.name,
      {
        event: 'cleanup.deleted',
        days: 5,
        deletedTokens: 2,
        deletedSessions: 3,
      },
    );

    expect(logger.debug).not.toHaveBeenCalledWith(
      'Token cleanup noop',
      TokenCleanupService.name,
      expect.anything(),
    );
  });

  it('logs error when cleanup fails (Error)', async () => {
    config.get.mockReturnValue(7);

    const error = new Error('failure');
    usersService.cleanRevokedTokens.mockRejectedValue(error);
    usersService.cleanInactiveSessions.mockResolvedValue(1);

    await service.handleCleanup();

    expect(logger.error).toHaveBeenCalledWith(
      'Token cleanup failed',
      error.stack,
      TokenCleanupService.name,
      expect.objectContaining({
        event: 'cleanup.fail',
        days: 7,
        errorName: 'Error',
        errorMessage: 'failure',
      }),
    );
  });

  it('logs error when cleanup fails (non-Error)', async () => {
    config.get.mockReturnValue(7);

    usersService.cleanRevokedTokens.mockRejectedValue('boom');
    usersService.cleanInactiveSessions.mockResolvedValue(1);

    await service.handleCleanup();

    expect(logger.error).toHaveBeenCalledWith(
      'Token cleanup failed',
      undefined,
      TokenCleanupService.name,
      expect.objectContaining({
        event: 'cleanup.fail',
        days: 7,
        errorName: 'UnknownError',
        errorMessage: 'boom',
      }),
    );
  });
});
