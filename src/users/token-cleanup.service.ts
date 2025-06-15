import { Injectable } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../users/users.service';
import { AppLogger } from 'src/logger/logger.service';

@Injectable()
export class TokenCleanupService {
  constructor(
    private usersService: UsersService,
    private config: ConfigService,
    private logger: AppLogger,
  ) {
    this.logger.setContext(TokenCleanupService.name);
  }

  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async handleCleanup() {
    const days = this.config.get<number>('TOKEN_CLEANUP_DAYS', 7);
    const deletedTokens = await this.usersService.cleanRevokedTokens(days);
    if (deletedTokens > 0) {
      this.logger.log(`🧹 Видалено ${deletedTokens} відкликаних токенів`);
    }

    const deletedSessions = await this.usersService.cleanInactiveSessions(days);
    if (deletedSessions > 0) {
      this.logger.log(`🧹 Видалено ${deletedSessions} неактивних сесій`);
    }
  }
}
