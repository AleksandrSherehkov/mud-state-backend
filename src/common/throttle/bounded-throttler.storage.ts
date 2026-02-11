import { Injectable, OnModuleDestroy } from '@nestjs/common';
import type { ThrottlerStorage } from '@nestjs/throttler';

type Entry = {
  hits: number;
  resetAtMs: number;
  lastSeenMs: number;
  blockedUntilMs: number;
};

type ThrottlerStorageRecordLike = {
  totalHits: number;
  timeToExpire: number;
  isBlocked: boolean;
  timeToBlockExpire: number;
};

function nowMs(): number {
  return Date.now();
}

@Injectable()
export class BoundedThrottlerStorage
  implements ThrottlerStorage, OnModuleDestroy
{
  private readonly store = new Map<string, Entry>();
  private readonly cleanupTimer: NodeJS.Timeout;

  constructor(
    private readonly maxKeys: number,
    private readonly cleanupIntervalMs: number,
  ) {
    const interval = Math.max(1_000, cleanupIntervalMs);
    this.cleanupTimer = setInterval(() => this.cleanupExpired(), interval);
    this.cleanupTimer.unref?.();
  }

  onModuleDestroy() {
    clearInterval(this.cleanupTimer);
    this.store.clear();
  }

  increment(
    key: string,
    ttl: number,
    limit: number,
    blockDuration: number,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    throttlerName: string,
  ): Promise<ThrottlerStorageRecordLike> {
    const t = nowMs();

    const ttlMs = Math.max(1, Math.floor(ttl * 1000));
    const blockMs = Math.max(0, Math.floor(blockDuration * 1000));
    const lim = Math.max(1, Math.floor(limit));

    let e = this.store.get(key);

    if (!e) {
      e = {
        hits: 0,
        resetAtMs: t + ttlMs,
        lastSeenMs: t,
        blockedUntilMs: 0,
      };
    } else if (e.resetAtMs <= t) {
      e = {
        hits: 0,
        resetAtMs: t + ttlMs,
        lastSeenMs: t,
        blockedUntilMs: e.blockedUntilMs > t ? e.blockedUntilMs : 0,
      };
    }

    if (e.blockedUntilMs > t) {
      e.lastSeenMs = t;
      this.touchLru(key, e);
      this.evictIfNeeded();

      return Promise.resolve({
        totalHits: e.hits,
        timeToExpire: Math.max(0, e.resetAtMs - t),
        isBlocked: true,
        timeToBlockExpire: Math.max(0, e.blockedUntilMs - t),
      });
    }

    e.hits += 1;
    e.lastSeenMs = t;

    if (e.hits > lim && blockMs > 0) {
      e.blockedUntilMs = t + blockMs;
    }

    this.touchLru(key, e);
    this.evictIfNeeded();

    return Promise.resolve({
      totalHits: e.hits,
      timeToExpire: Math.max(0, e.resetAtMs - t),
      isBlocked: e.blockedUntilMs > t,
      timeToBlockExpire: Math.max(0, e.blockedUntilMs - t),
    });
  }

  private touchLru(key: string, e: Entry) {
    this.store.delete(key);
    this.store.set(key, e);
  }

  private evictIfNeeded() {
    if (this.store.size <= this.maxKeys) return;

    this.cleanupExpired();
    if (this.store.size <= this.maxKeys) return;

    const t = nowMs();

    while (this.store.size > this.maxKeys) {
      let victimKey: string | undefined;

      for (const [k, e] of this.store) {
        const isBlocked = e.blockedUntilMs > t;
        if (!isBlocked) {
          victimKey = k;
          break;
        }
      }

      if (!victimKey) {
        victimKey = this.store.keys().next().value as string | undefined;
      }

      if (!victimKey) break;
      this.store.delete(victimKey);
    }
  }

  private cleanupExpired() {
    const t = nowMs();

    for (const [k, e] of this.store) {
      const ttlExpired = e.resetAtMs <= t;
      const notBlocked = e.blockedUntilMs <= t;

      if (ttlExpired && notBlocked) this.store.delete(k);
    }
  }
}
