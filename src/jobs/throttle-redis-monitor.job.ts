import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { SchedulerRegistry } from '@nestjs/schedule';
import { CronJob } from 'cron';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';

import { AppLogger } from 'src/logger/logger.service';

const JOB_NAME = 'throttle-redis-monitor-job';

function parseInfoToMap(info: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of info.split('\n')) {
    const s = line.trim();
    if (!s || s.startsWith('#')) continue;
    const i = s.indexOf(':');
    if (i <= 0) continue;
    out[s.slice(0, i)] = s.slice(i + 1).trim();
  }
  return out;
}

function parseKeyspaceKeys(infoKeyspace: string): number {
  let total = 0;
  for (const line of infoKeyspace.split('\n')) {
    const s = line.trim();
    if (!s.startsWith('db')) continue;
    const m = s.match(/keys=(\d+)/);
    if (m) total += Number(m[1] ?? 0);
  }
  return total;
}

@Injectable()
export class ThrottleRedisMonitorJob implements OnModuleInit, OnModuleDestroy {
  private client: Redis | null = null;
  private lastEvictedKeys = 0;

  constructor(
    private readonly config: ConfigService,
    private readonly schedulerRegistry: SchedulerRegistry,
    private readonly logger: AppLogger,
  ) {
    this.logger.setContext(ThrottleRedisMonitorJob.name);
  }

  onModuleInit() {
    const enabled = this.config.get<boolean>(
      'THROTTLE_REDIS_MONITOR_ENABLED',
      true,
    );
    if (!enabled) {
      this.logger.debug(
        'Throttle Redis monitor disabled',
        ThrottleRedisMonitorJob.name,
        {
          event: 'throttleRedisMonitor.disabled',
        },
      );
      return;
    }

    const cron = this.config.get<string>(
      'THROTTLE_REDIS_MONITOR_CRON',
      '*/1 * * * *',
    );
    const job = new CronJob(cron, () => void this.tick());

    this.schedulerRegistry.addCronJob(JOB_NAME, job);
    job.start();

    this.logger.debug(
      'Throttle Redis monitor job registered',
      ThrottleRedisMonitorJob.name,
      {
        event: 'throttleRedisMonitor.init',
        cron,
      },
    );
  }

  async onModuleDestroy(): Promise<void> {
    try {
      const job = this.schedulerRegistry.getCronJob(JOB_NAME);
      await Promise.resolve(job.stop());
      this.schedulerRegistry.deleteCronJob(JOB_NAME);
    } catch {
      // noop
    }

    const c = this.client;
    this.client = null;
    if (c) {
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
  }

  private async getClient(): Promise<Redis> {
    if (this.client) return this.client;

    const url = String(
      this.config.get<string>('THROTTLE_REDIS_URL') ?? '',
    ).trim();
    if (!url) throw new Error('THROTTLE_REDIS_URL is required for monitor');

    const timeoutMs =
      Number(
        this.config.get('THROTTLE_REDIS_HEALTHCHECK_TIMEOUT_MS') ?? 1000,
      ) || 1000;

    const client = new Redis(url, {
      lazyConnect: true,
      enableOfflineQueue: false,
      maxRetriesPerRequest: 1,
      connectTimeout: timeoutMs,
    });

    await client.connect();
    this.client = client;
    return client;
  }

  private async tick() {
    const keysWarn = this.config.get<number>(
      'THROTTLE_REDIS_MONITOR_KEYS_WARN',
      80_000,
    );
    const evictDeltaWarn = this.config.get<number>(
      'THROTTLE_REDIS_MONITOR_EVICTIONS_WARN_DELTA',
      1,
    );

    try {
      const c = await this.getClient();

      const [statsRaw, keyspaceRaw, memRaw] = await Promise.all([
        c.info('stats'),
        c.info('keyspace'),
        c.info('memory'),
      ]);

      const stats = parseInfoToMap(statsRaw);
      const mem = parseInfoToMap(memRaw);

      const evictedKeys = Number(stats.evicted_keys ?? 0) || 0;
      const keysTotal = parseKeyspaceKeys(keyspaceRaw);

      const usedMemory = Number(mem.used_memory ?? 0) || 0;
      const ops = Number(stats.instantaneous_ops_per_sec ?? 0) || 0;

      const evictedDelta = Math.max(0, evictedKeys - this.lastEvictedKeys);
      this.lastEvictedKeys = evictedKeys;

      // Always emit a compact debug line (cheap, useful)
      this.logger.debug('Throttle Redis stats', ThrottleRedisMonitorJob.name, {
        event: 'throttleRedisMonitor.tick',
        keysTotal,
        evictedKeys,
        evictedDelta,
        usedMemory,
        ops,
      });

      if (keysTotal >= keysWarn) {
        this.logger.warn(
          'Throttle Redis keyspace is high',
          ThrottleRedisMonitorJob.name,
          {
            event: 'throttleRedisMonitor.warn.keys',
            keysTotal,
            keysWarn,
          },
        );
      }

      if (evictedDelta >= evictDeltaWarn) {
        this.logger.warn(
          'Throttle Redis evictions detected',
          ThrottleRedisMonitorJob.name,
          {
            event: 'throttleRedisMonitor.warn.evictions',
            evictedDelta,
            evictDeltaWarn,
            evictedKeys,
          },
        );
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      const trace = err instanceof Error ? err.stack : undefined;

      this.logger.error(
        'Throttle Redis monitor tick failed',
        trace,
        ThrottleRedisMonitorJob.name,
        {
          event: 'throttleRedisMonitor.fail',
          errorMessage: msg,
        },
      );
    }
  }
}
