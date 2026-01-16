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

  let logger: {
    setContext: jest.Mock<void, [context: string]>;
    log: jest.Mock<void, [message: string, context?: string]>;
    error: jest.Mock<void, [message: string, trace?: string, context?: string]>;
    warn: jest.Mock<void, [message: string, context?: string]>;
    debug: jest.Mock<void, [message: string, context?: string]>;
    verbose: jest.Mock<void, [message: string, context?: string]>;
    silly: jest.Mock<void, [message: string, context?: string]>;
  };

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
      setContext: jest.fn<void, [string]>(),
      log: jest.fn<void, [string, (string | undefined)?]>(),
      error: jest.fn<
        void,
        [string, (string | undefined)?, (string | undefined)?]
      >(),
      warn: jest.fn<void, [string, (string | undefined)?]>(),
      debug: jest.fn<void, [string, (string | undefined)?]>(),
      verbose: jest.fn<void, [string, (string | undefined)?]>(),
      silly: jest.fn<void, [string, (string | undefined)?]>(),
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
  });

  it('logs deleted tokens and sessions when counts are positive', async () => {
    config.get.mockReturnValue(5);
    usersService.cleanRevokedTokens.mockResolvedValue(2);
    usersService.cleanInactiveSessions.mockResolvedValue(3);

    await service.handleCleanup();

    expect(usersService.cleanRevokedTokens).toHaveBeenCalledWith(5);
    expect(usersService.cleanInactiveSessions).toHaveBeenCalledWith(5);

    expect(logger.log).toHaveBeenCalledWith(
      '🧹 Видалено 2 відкликаних токенів',
    );
    expect(logger.log).toHaveBeenCalledWith('🧹 Видалено 3 неактивних сесій');
  });

  it('does not log when counts are zero', async () => {
    config.get.mockReturnValue(7);
    usersService.cleanRevokedTokens.mockResolvedValue(0);
    usersService.cleanInactiveSessions.mockResolvedValue(0);

    await service.handleCleanup();

    expect(logger.log).not.toHaveBeenCalled();
    expect(logger.error).not.toHaveBeenCalled();
  });

  it('logs only token message when only tokens are deleted', async () => {
    config.get.mockReturnValue(7);
    usersService.cleanRevokedTokens.mockResolvedValue(2);
    usersService.cleanInactiveSessions.mockResolvedValue(0);

    await service.handleCleanup();

    expect(logger.log).toHaveBeenCalledTimes(1);
    expect(logger.log).toHaveBeenCalledWith(
      '🧹 Видалено 2 відкликаних токенів',
    );
  });

  it('logs only session message when only sessions are deleted', async () => {
    config.get.mockReturnValue(7);
    usersService.cleanRevokedTokens.mockResolvedValue(0);
    usersService.cleanInactiveSessions.mockResolvedValue(4);

    await service.handleCleanup();

    expect(logger.log).toHaveBeenCalledTimes(1);
    expect(logger.log).toHaveBeenCalledWith('🧹 Видалено 4 неактивних сесій');
  });

  it('logs error when cleanup fails (Error)', async () => {
    config.get.mockReturnValue(7);

    const error = new Error('failure');
    usersService.cleanRevokedTokens.mockRejectedValue(error);
    usersService.cleanInactiveSessions.mockResolvedValue(1); // не важно, Promise.all упадёт

    await service.handleCleanup();

    expect(logger.error).toHaveBeenCalledWith('❌ Cleanup failed', error.stack);
    expect(logger.log).not.toHaveBeenCalled();
  });

  it('logs error when cleanup fails (non-Error)', async () => {
    config.get.mockReturnValue(7);

    usersService.cleanRevokedTokens.mockRejectedValue('boom');
    usersService.cleanInactiveSessions.mockResolvedValue(1);

    await service.handleCleanup();

    expect(logger.error).toHaveBeenCalledWith('❌ Cleanup failed', 'boom');
    expect(logger.log).not.toHaveBeenCalled();
  });
});
