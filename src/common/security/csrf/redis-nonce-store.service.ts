import { Injectable } from '@nestjs/common';
import Redis from 'ioredis';
import { SecurityPolicyService } from '../policy/security-policy.service';

@Injectable()
export class RedisNonceStoreService {
  private readonly redis: Redis | null;

  constructor(private readonly policy: SecurityPolicyService) {
    const url = (this.policy.get().csrf.m2m.redisUrl ?? '').trim();

    if (!url) {
      this.redis = null;
      return;
    }

    this.redis = new Redis(url, {
      lazyConnect: true,
      enableOfflineQueue: false,
      maxRetriesPerRequest: 1,
    });
  }

  async setNxEx(key: string, ttlSec: number): Promise<boolean> {
    if (!this.redis) return false;
    await this.redis.connect().catch(() => undefined);
    const res = await this.redis.set(key, '1', 'EX', ttlSec, 'NX');
    return res === 'OK';
  }

  async del(key: string): Promise<void> {
    if (!this.redis) return;
    try {
      await this.redis.del(key);
    } catch {
      // ignore
    }
  }
}
