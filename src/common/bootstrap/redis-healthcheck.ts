import { ConfigService } from '@nestjs/config';
import { AppLogger } from 'src/logger/logger.service';

type RedisLike = {
  connect(): Promise<void>;
  ping(): Promise<string>;
  quit(): Promise<void>;
};

type RedisCtor = new (
  url: string,
  options: {
    lazyConnect: boolean;
    maxRetriesPerRequest: number;
    enableOfflineQueue: boolean;
  },
) => RedisLike;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null;
}

function getRedisCtor(mod: unknown): RedisCtor {
  if (typeof mod === 'function') return mod as unknown as RedisCtor;

  if (isRecord(mod)) {
    const candidate = (mod.default ?? mod) as unknown;
    if (typeof candidate === 'function')
      return candidate as unknown as RedisCtor;
  }

  throw new Error('Invalid ioredis export (expected constructor function)');
}

async function pingRedisOrThrow(redisUrl: string, timeoutMs: number) {
  const mod = (await import('ioredis')) as unknown;
  const Redis = getRedisCtor(mod);

  const client = new Redis(redisUrl, {
    lazyConnect: true,
    maxRetriesPerRequest: 1,
    enableOfflineQueue: false,
  });

  await Promise.race([
    (async () => {
      await client.connect();
      const pong = await client.ping();
      await client.quit();

      if (pong.toUpperCase() !== 'PONG') {
        throw new Error(`Unexpected Redis PING response: ${pong}`);
      }
    })(),
    new Promise<void>((_, rej) =>
      setTimeout(
        () => rej(new Error(`Redis PING timeout ${timeoutMs}ms`)),
        timeoutMs,
      ),
    ),
  ]);
}

export type RedisHealthStatus = 'connected' | 'unavailable' | 'skipped';

export async function checkRedisOrThrow(
  config: ConfigService,
  logger: AppLogger,
): Promise<RedisHealthStatus> {
  const redisHealthcheck = Boolean(
    config.get('THROTTLE_REDIS_HEALTHCHECK') ?? true,
  );
  if (!redisHealthcheck) return 'skipped';

  const redisUrl = String(config.get('THROTTLE_REDIS_URL') ?? '').trim();
  const timeoutMs = Number(
    config.get('THROTTLE_REDIS_HEALTHCHECK_TIMEOUT_MS') ?? 1000,
  );
  const strict = Boolean(
    config.get('THROTTLE_REDIS_HEALTHCHECK_STRICT') ?? true,
  );

  if (!redisUrl) {
    if (strict) {
      throw new Error('SECURITY: THROTTLE_REDIS_URL is not set');
    }

    logger.warn(
      '⚠️ Redis healthcheck skipped/unavailable (non-strict): THROTTLE_REDIS_URL is not set',
      'Bootstrap',
    );
    return 'unavailable';
  }

  try {
    await pingRedisOrThrow(redisUrl, timeoutMs);
    return 'connected';
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);

    if (strict) {
      throw new Error(`SECURITY: Redis throttling backend unavailable: ${msg}`);
    }

    logger.warn(
      `⚠️ Redis throttling backend unavailable (non-strict): ${msg}`,
      'Bootstrap',
    );
    return 'unavailable';
  }
}
