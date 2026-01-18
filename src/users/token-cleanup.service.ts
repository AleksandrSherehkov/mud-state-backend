import { Injectable } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../users/users.service';
import { AppLogger } from 'src/logger/logger.service';

function errMeta(err: unknown) {
  if (err instanceof Error) {
    return { errorName: err.name, errorMessage: err.message };
  }
  return { errorName: 'UnknownError', errorMessage: String(err) };
}

@Injectable()
export class TokenCleanupService {
  constructor(
    private readonly usersService: UsersService,
    private readonly config: ConfigService,
    private readonly logger: AppLogger,
  ) {
    this.logger.setContext(TokenCleanupService.name);
  }

  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async handleCleanup() {
    const days = this.config.get<number>('TOKEN_CLEANUP_DAYS', 7);

    this.logger.debug('Token cleanup start', TokenCleanupService.name, {
      event: 'cleanup.start',
      days,
    });

    try {
      const [deletedTokens, deletedSessions] = await Promise.all([
        this.usersService.cleanRevokedTokens(days),
        this.usersService.cleanInactiveSessions(days),
      ]);

      this.logger.debug('Token cleanup finished', TokenCleanupService.name, {
        event: 'cleanup.done',
        days,
        deletedTokens,
        deletedSessions,
      });

      if (deletedTokens > 0 || deletedSessions > 0) {
        this.logger.log(
          'Token cleanup deleted records',
          TokenCleanupService.name,
          {
            event: 'cleanup.deleted',
            days,
            deletedTokens,
            deletedSessions,
          },
        );
      } else {
        this.logger.debug('Token cleanup noop', TokenCleanupService.name, {
          event: 'cleanup.noop',
          days,
        });
      }
    } catch (err: unknown) {
      const trace = err instanceof Error ? err.stack : undefined;

      this.logger.error(
        'Token cleanup failed',
        trace,
        TokenCleanupService.name,
        {
          event: 'cleanup.fail',
          days,
          ...errMeta(err),
        },
      );
    }
  }
}
