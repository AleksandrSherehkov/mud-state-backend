import { Injectable, NotFoundException } from '@nestjs/common';

import { UsersService } from 'src/users/users.service';
import { SessionLifecycleService } from 'src/sessions/session-lifecycle.service';
import { AppLogger } from 'src/logger/logger.service';

@Injectable()
export class LogoutUseCase {
  constructor(
    private readonly users: UsersService,
    private readonly lifecycle: SessionLifecycleService,
    private readonly logger: AppLogger,
  ) {
    this.logger.setContext(LogoutUseCase.name);
  }

  async execute(
    userId: string,
  ): Promise<{ loggedOut: true; terminatedAt: string } | null> {
    const user = await this.users.findById(userId);
    if (!user) {
      this.logger.warn('Logout failed: user not found', LogoutUseCase.name, {
        event: 'auth.logout.fail',
        reason: 'user_not_found',
        userId,
      });
      throw new NotFoundException('Користувача не знайдено');
    }

    const { revokedTokens, terminatedSessions } =
      await this.lifecycle.revokeAllAndTerminateAll({
        userId,
        reason: 'logout',
      });

    if (revokedTokens === 0 && terminatedSessions === 0) {
      this.logger.log(
        'Logout noop (nothing to revoke/terminate)',
        LogoutUseCase.name,
        {
          event: 'auth.logout.noop',
          userId,
        },
      );
      return null;
    }

    this.logger.log('Logout success', LogoutUseCase.name, {
      event: 'auth.logout.success',
      userId,
      revoked: revokedTokens,
      terminated: terminatedSessions,
    });

    return { loggedOut: true, terminatedAt: new Date().toISOString() };
  }
}
