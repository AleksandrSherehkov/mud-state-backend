import { Injectable } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../users/users.service';
import { AppLogger } from 'src/logger/logger.service';

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

    try {
      const [deletedTokens, deletedSessions] = await Promise.all([
        this.usersService.cleanRevokedTokens(days),
        this.usersService.cleanInactiveSessions(days),
      ]);

      if (deletedTokens > 0) {
        this.logger.log(`🧹 Видалено ${deletedTokens} відкликаних токенів`);
      }
      if (deletedSessions > 0) {
        this.logger.log(`🧹 Видалено ${deletedSessions} неактивних сесій`);
      }
    } catch (err: unknown) {
      this.logger.error(
        `❌ Cleanup failed`,
        err instanceof Error ? err.stack : String(err),
      );
    }
  }
}
