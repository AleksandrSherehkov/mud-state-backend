import { ForbiddenException, Injectable } from '@nestjs/common';
import { SecurityPolicyService } from '../policy/security-policy.service';
import { RedisNonceStoreService } from './redis-nonce-store.service';

@Injectable()
export class CsrfM2mReplayService {
  constructor(
    private readonly policy: SecurityPolicyService,
    private readonly store: RedisNonceStoreService,
  ) {}

  async assertNonceOnce(
    kid: string,
    ts: number,
    nonce: string,
  ): Promise<string> {
    const p = this.policy.get().csrf.m2m;

    if (!p.redisUrl) {
      throw new ForbiddenException('CSRF validation failed (non-browser)');
    }

    const key = `${p.noncePrefix}${kid}:${ts}:${nonce}`;
    const ok = await this.store.setNxEx(key, p.replayWindowSec);

    if (!ok)
      throw new ForbiddenException('CSRF validation failed (m2m_replay)');
    return key;
  }

  async rollbackNonce(key: string): Promise<void> {
    await this.store.del(key);
  }
}
