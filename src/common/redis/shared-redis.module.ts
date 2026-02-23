import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import Redis from 'ioredis';

import { createRedisClientOrNull } from './shared-redis.factory';
import { SharedRedisShutdownService } from './shared-redis.shutdown.service';
import { AUTH_CHALLENGE_REDIS, CSRF_M2M_REDIS } from './shared-redis.constants';

@Module({
  imports: [ConfigModule],
  providers: [
    {
      provide: CSRF_M2M_REDIS,
      inject: [ConfigService],
      useFactory: async (config: ConfigService): Promise<Redis> => {
        const appEnv = String(config.get('APP_ENV') ?? 'development');
        const isProd = appEnv === 'production';

        const strict =
          (config.get<boolean>('CSRF_M2M_REDIS_STRICT') ?? isProd) === true;

        const connectTimeoutMs =
          Number(config.get('CSRF_M2M_REDIS_CONNECT_TIMEOUT_MS') ?? 1000) ||
          1000;

        const client = await createRedisClientOrNull({
          name: 'CSRF_M2M',
          url: config.get<string>('CSRF_M2M_REDIS_URL'),
          strict,
          connectTimeoutMs,
        });

        if (!client) {
          throw new Error(
            'REDIS: CSRF_M2M client is null (expected strict=true)',
          );
        }

        return client;
      },
    },
    {
      provide: AUTH_CHALLENGE_REDIS,
      inject: [ConfigService],
      useFactory: async (config: ConfigService): Promise<Redis> => {
        const appEnv = String(config.get('APP_ENV') ?? 'development');
        const isProd = appEnv === 'production';

        const strict =
          (config.get<boolean>('AUTH_CHALLENGE_REDIS_STRICT') ?? isProd) ===
          true;

        const connectTimeoutMs =
          Number(
            config.get('AUTH_CHALLENGE_REDIS_CONNECT_TIMEOUT_MS') ?? 1000,
          ) || 1000;

        const client = await createRedisClientOrNull({
          name: 'AUTH_CHALLENGE',
          url: config.get<string>('AUTH_CHALLENGE_REDIS_URL'),
          strict,
          connectTimeoutMs,
        });

        if (!client) {
          throw new Error(
            'REDIS: AUTH_CHALLENGE client is null (expected strict=true)',
          );
        }

        return client;
      },
    },
    SharedRedisShutdownService,
  ],
  exports: [CSRF_M2M_REDIS, AUTH_CHALLENGE_REDIS],
})
export class SharedRedisModule {}
