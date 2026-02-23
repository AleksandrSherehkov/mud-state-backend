import { Inject, Injectable, OnModuleDestroy } from '@nestjs/common';
import Redis from 'ioredis';

import { AUTH_CHALLENGE_REDIS, CSRF_M2M_REDIS } from './shared-redis.constants';

@Injectable()
export class SharedRedisShutdownService implements OnModuleDestroy {
  constructor(
    @Inject(CSRF_M2M_REDIS) private readonly csrfRedis: Redis,
    @Inject(AUTH_CHALLENGE_REDIS) private readonly authChallengeRedis: Redis,
  ) {}

  async onModuleDestroy() {
    await Promise.allSettled([
      this.safeQuit(this.csrfRedis),
      this.safeQuit(this.authChallengeRedis),
    ]);
  }

  private async safeQuit(client: Redis) {
    try {
      await client.quit();
    } catch {
      try {
        client.disconnect();
      } catch {
        // ignore
      }
    }
  }
}
