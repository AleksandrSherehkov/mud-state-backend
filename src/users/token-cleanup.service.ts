import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../users/users.service';

@Injectable()
export class TokenCleanupService {
  private readonly logger = new Logger(TokenCleanupService.name);

  constructor(
    private usersService: UsersService,
    private config: ConfigService,
  ) {}

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
