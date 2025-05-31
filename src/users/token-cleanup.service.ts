import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { UsersService } from '../users/users.service';

@Injectable()
export class TokenCleanupService {
  private readonly logger = new Logger(TokenCleanupService.name);

  constructor(private usersService: UsersService) {}

  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async handleCleanup() {
    const deleted = await this.usersService.cleanRevokedTokens(7);
    if (deleted > 0) {
      this.logger.log(`🧹 Видалено ${deleted} відкликаних токенів`);
    }
  }
}
