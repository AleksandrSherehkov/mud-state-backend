import { Injectable, OnModuleDestroy } from '@nestjs/common';
import type { ThrottlerStorage } from '@nestjs/throttler';

type ThrottlerStorageRecordLike = {
  totalHits: number;
  timeToExpire: number;
  isBlocked: boolean;
  timeToBlockExpire: number;
};

const LUA_INCREMENT = `
-- KEYS[1] = hitsKey
-- KEYS[2] = blockKey
-- ARGV[1] = nowMs
-- ARGV[2] = ttlMs
-- ARGV[3] = limit
-- ARGV[4] = blockMs

local now = tonumber(ARGV[1])
local ttlMs = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local blockMs = tonumber(ARGV[4])

local blockedUntil = redis.call('GET', KEYS[2])
if blockedUntil then
  blockedUntil = tonumber(blockedUntil)
  if blockedUntil > now then
    local pttlHits = redis.call('PTTL', KEYS[1])
    local pttlBlock = redis.call('PTTL', KEYS[2])
    if pttlHits < 0 then pttlHits = 0 end
    if pttlBlock < 0 then pttlBlock = 0 end
    local hitsVal = redis.call('GET', KEYS[1])
    local hits = tonumber(hitsVal or '0')
    return {hits, pttlHits, 1, pttlBlock}
  end
end

local hits = redis.call('INCR', KEYS[1])
if hits == 1 then
  redis.call('PEXPIRE', KEYS[1], ttlMs)
end

local pttlHits = redis.call('PTTL', KEYS[1])
if pttlHits < 0 then pttlHits = 0 end

local isBlocked = 0
local pttlBlock = 0

if hits > limit and blockMs > 0 then
  local newBlockedUntil = now + blockMs
  redis.call('SET', KEYS[2], newBlockedUntil, 'PX', blockMs)
  isBlocked = 1
  pttlBlock = redis.call('PTTL', KEYS[2])
  if pttlBlock < 0 then pttlBlock = 0 end
end

return {hits, pttlHits, isBlocked, pttlBlock}
`;

function ceilSecFromMs(ms: number): number {
  if (!Number.isFinite(ms) || ms <= 0) return 0;
  return Math.ceil(ms / 1000);
}

/**
 * Минимальный контракт Redis-клиента, который нам нужен.
 * Не тянем типы ioredis, чтобы Redis оставался optional dependency.
 */
type RedisClientLike = {
  connect(): Promise<void>;
  quit(): Promise<void>;
  disconnect(): void;
  eval(
    script: string,
    numberOfKeys: number,
    ...args: Array<string | number>
  ): Promise<unknown>;
};

type RedisCtor = new (
  url: string,
  options: {
    lazyConnect: boolean;
    maxRetriesPerRequest: number;
    enableOfflineQueue: boolean;
  },
) => RedisClientLike;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null;
}

function getRedisCtor(mod: unknown): RedisCtor {
  if (typeof mod === 'function') {
    return mod as unknown as RedisCtor;
  }

  if (isRecord(mod)) {
    const candidate = (mod.default ?? mod) as unknown;
    if (typeof candidate === 'function') {
      return candidate as unknown as RedisCtor;
    }
  }

  throw new Error('Invalid ioredis export (expected constructor function)');
}

function isLuaResultTuple(v: unknown): v is [number, number, number, number] {
  return (
    Array.isArray(v) &&
    v.length >= 4 &&
    typeof v[0] === 'number' &&
    typeof v[1] === 'number' &&
    typeof v[2] === 'number' &&
    typeof v[3] === 'number'
  );
}

@Injectable()
export class RedisThrottlerStorage
  implements ThrottlerStorage, OnModuleDestroy
{
  private client: RedisClientLike | null = null;

  constructor(
    private readonly redisUrl: string,
    private readonly prefix: string = 'throttle:',
  ) {}

  private async getClient(): Promise<RedisClientLike> {
    if (this.client) return this.client;

    const mod = (await import('ioredis')) as unknown;
    const Redis = getRedisCtor(mod);

    const client = new Redis(this.redisUrl, {
      lazyConnect: true,
      maxRetriesPerRequest: 2,
      enableOfflineQueue: false,
    });

    await client.connect();
    this.client = client;

    return client;
  }

  async onModuleDestroy() {
    const c = this.client;
    this.client = null;

    if (!c) return;

    try {
      await c.quit();
    } catch {
      try {
        c.disconnect();
      } catch {
        // ignore
      }
    }
  }

  async increment(
    key: string,
    ttl: number,
    limit: number,
    blockDuration: number,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    throttlerName: string,
  ): Promise<ThrottlerStorageRecordLike> {
    const client = await this.getClient();

    const now = Date.now();

    const ttlMs = Math.max(1, Math.floor(ttl * 1000));
    const blockMs = Math.max(0, Math.floor(blockDuration * 1000));
    const lim = Math.max(1, Math.floor(limit));

    const hitsKey = `${this.prefix}${key}`;
    const blockKey = `${this.prefix}${key}:block`;

    const raw = await client.eval(
      LUA_INCREMENT,
      2,
      hitsKey,
      blockKey,
      now,
      ttlMs,
      lim,
      blockMs,
    );

    const res: [number, number, number, number] = isLuaResultTuple(raw)
      ? raw
      : [0, 0, 0, 0];

    const totalHits = Number(res[0] ?? 0);
    const pttlHits = Number(res[1] ?? 0);
    const isBlocked = Number(res[2] ?? 0) === 1;
    const pttlBlock = Number(res[3] ?? 0);

    return {
      totalHits,
      timeToExpire: ceilSecFromMs(pttlHits),
      isBlocked,
      timeToBlockExpire: ceilSecFromMs(pttlBlock),
    };
  }
}
