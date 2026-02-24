import { Inject, Injectable } from '@nestjs/common';
import Redis from 'ioredis';

import { CSRF_M2M_REDIS } from 'src/common/redis/shared-redis.constants';

@Injectable()
export class RedisNonceStoreService {
  constructor(@Inject(CSRF_M2M_REDIS) private readonly redis: Redis) {}

  async setNxEx(key: string, ttlSec: number): Promise<boolean> {
    const res = await this.redis.set(key, '1', 'EX', ttlSec, 'NX');
    return res === 'OK';
  }

  async del(key: string): Promise<void> {
    try {
      await this.redis.del(key);
    } catch {
      // ignore
    }
  }
}
