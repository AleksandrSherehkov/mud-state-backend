import {
  ForbiddenException,
  Inject,
  Injectable,
  ServiceUnavailableException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';
import { createHash, randomBytes } from 'node:crypto';

import { AUTH_CHALLENGE_REDIS } from 'src/common/redis/shared-redis.constants';
import { AppLogger } from 'src/logger/logger.service';

type ChallengeHeaders = { nonce?: string; solution?: string };

type ChallengeIssued = {
  nonce: string;
  difficultyBits: number;
  ttlSec: number;
};

@Injectable()
export class AuthChallengeService {
  private static readonly ISSUE_RETRIES = 5;
  private static readonly METRIC_ISSUE_FAIL_TOTAL =
    'challenge_issue_fail_total';

  constructor(
    private readonly config: ConfigService,
    @Inject(AUTH_CHALLENGE_REDIS)
    private readonly redis: Redis,
    private readonly logger: AppLogger,
  ) {
    this.logger.setContext(AuthChallengeService.name);
  }

  private enabled(): boolean {
    return Boolean(this.config.get<boolean>('AUTH_CHALLENGE_ENABLED') ?? true);
  }

  private windowSec(): number {
    return Number(this.config.get('AUTH_CHALLENGE_WINDOW_SEC') ?? 900);
  }

  private afterFails(): number {
    return Number(this.config.get('AUTH_CHALLENGE_AFTER_FAILS') ?? 6);
  }

  private difficultyBits(): number {
    return Number(this.config.get('AUTH_CHALLENGE_DIFFICULTY_BITS') ?? 18);
  }

  private nonceTtlSec(): number {
    return Number(this.config.get('AUTH_CHALLENGE_NONCE_TTL_SEC') ?? 120);
  }

  private prefix(): string {
    return String(
      this.config.get('AUTH_CHALLENGE_PREFIX') ?? 'auth:chal:',
    ).trim();
  }

  private keyFailId(idHash: string): string {
    return `${this.prefix()}fail:id:${idHash}`;
  }

  private keyFailIp(ip: string): string {
    return `${this.prefix()}fail:ip:${ip}`;
  }

  private keyNonce(nonce: string): string {
    return `${this.prefix()}nonce:${nonce}`;
  }

  private assertEnabledOrNoop(): boolean {
    return this.enabled();
  }

  async recordLoginFail(params: {
    identifierHash: string;
    ip?: string;
  }): Promise<void> {
    if (!this.assertEnabledOrNoop()) return;

    const id = params.identifierHash.trim();
    const ip = (params.ip ?? '').trim();
    const ttl = this.windowSec();

    await this.redis
      .multi()
      .incr(this.keyFailId(id))
      .expire(this.keyFailId(id), ttl, 'NX')
      .exec();

    if (ip && ip !== 'unknown') {
      await this.redis
        .multi()
        .incr(this.keyFailIp(ip))
        .expire(this.keyFailIp(ip), ttl, 'NX')
        .exec();
    }
  }

  async clearOnSuccess(params: {
    identifierHash: string;
    ip?: string;
  }): Promise<void> {
    if (!this.assertEnabledOrNoop()) return;

    const id = params.identifierHash.trim();
    const ip = (params.ip ?? '').trim();

    const keys = [this.keyFailId(id)];
    if (ip && ip !== 'unknown') keys.push(this.keyFailIp(ip));

    try {
      await this.redis.del(...keys);
    } catch {
      // ignore
    }
  }

  private async shouldRequire(params: {
    identifierHash: string;
    ip?: string;
  }): Promise<boolean> {
    if (!this.enabled()) return false;

    const id = params.identifierHash.trim();
    const ip = (params.ip ?? '').trim();

    const keys = [this.keyFailId(id)];
    if (ip && ip !== 'unknown') keys.push(this.keyFailIp(ip));

    const vals = await this.redis.mget(...keys);
    const counts = vals.map((v) => Number(v ?? 0));

    return counts.some((c) => Number.isFinite(c) && c >= this.afterFails());
  }

  private issueNonce(): string {
    return randomBytes(18).toString('base64url');
  }

  private sha256Hex(s: string): string {
    return createHash('sha256').update(s, 'utf8').digest('hex');
  }

  private leadingZeroBits(hex: string): number {
    const LZ = [4, 3, 2, 2, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0];

    let bits = 0;

    for (const ch of hex) {
      const n = Number.parseInt(ch, 16);
      if (!Number.isFinite(n)) return bits;

      if (n === 0) {
        bits += 4;
        continue;
      }

      bits += LZ[n] ?? 0;
      break;
    }

    return bits;
  }

  private validateSolution(solution: string): boolean {
    if (!solution) return false;
    if (solution.length > 16) return false;
    return /^\d{1,16}$/.test(solution);
  }

  private powOk(nonce: string, solution: string): boolean {
    if (!this.validateSolution(solution)) return false;
    const h = this.sha256Hex(`${nonce}.${solution}`);
    return this.leadingZeroBits(h) >= this.difficultyBits();
  }

  private async newChallenge(): Promise<ChallengeIssued> {
    const ttlSec = this.nonceTtlSec();

    let lastErr: unknown;

    for (
      let attempt = 1;
      attempt <= AuthChallengeService.ISSUE_RETRIES;
      attempt++
    ) {
      const nonce = this.issueNonce();

      try {
        const ok = await this.redis.set(
          this.keyNonce(nonce),
          '1',
          'EX',
          ttlSec,
          'NX',
        );

        if (ok === 'OK') {
          return { nonce, difficultyBits: this.difficultyBits(), ttlSec };
        }
      } catch (e) {
        lastErr = e;
      }
    }

    const trace =
      lastErr instanceof Error ? (lastErr.stack ?? lastErr.message) : undefined;

    this.logger.error(
      'Auth challenge issue failed (bounded retries exhausted)',
      trace,
      AuthChallengeService.name,
      {
        event: 'auth.challenge.issue_failed',
        metric: AuthChallengeService.METRIC_ISSUE_FAIL_TOTAL,
        attempts: AuthChallengeService.ISSUE_RETRIES,
        ttlSec,
        hasError: Boolean(lastErr),
      },
    );

    throw new ServiceUnavailableException({
      code: 'challenge_unavailable',
      message: 'Auth challenge temporarily unavailable',
    });
  }

  private async consumeNonce(nonce: string): Promise<boolean> {
    const key = this.keyNonce(nonce);
    const val = await this.redis.get(key);
    if (!val) return false;

    await this.redis.del(key);
    return true;
  }

  async assertSatisfiedOrThrow(params: {
    identifierHash: string;
    ip?: string;
    headers?: ChallengeHeaders;
  }): Promise<void> {
    const need = await this.shouldRequire({
      identifierHash: params.identifierHash,
      ip: params.ip,
    });
    if (!need) return;

    const nonce = (params.headers?.nonce ?? '').trim();
    const solution = (params.headers?.solution ?? '').trim();

    if (!nonce || !solution) {
      const ch = await this.newChallenge();
      throw new ForbiddenException({
        code: 'challenge_required',
        challenge: ch,
      });
    }

    const nonceOk = await this.consumeNonce(nonce);
    if (!nonceOk) {
      const ch = await this.newChallenge();
      throw new ForbiddenException({
        code: 'challenge_required',
        challenge: ch,
      });
    }

    if (!this.powOk(nonce, solution)) {
      const ch = await this.newChallenge();
      throw new ForbiddenException({
        code: 'challenge_required',
        challenge: ch,
      });
    }
  }
}
