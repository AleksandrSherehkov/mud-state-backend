import { Module } from '@nestjs/common';
import { ThrottlerModule } from '@nestjs/throttler';
import type { ThrottlerStorage } from '@nestjs/throttler';

import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { ConfigModule, ConfigService } from '@nestjs/config';

import { ScheduleModule } from '@nestjs/schedule';
import { LoggerModule } from './logger/logger.module';
import { APP_FILTER, APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';

import { GlobalExceptionFilter } from './common/http/filters/global-exception.filter';
import { RequestContextModule } from './common/request-context/request-context.module';
import { JobsModule } from './jobs/jobs.module';

import { resolveEnvFilePath } from './config/env-path';
import { envValidationSchema } from './config/env.validation';

import { SecurityModule } from './common/security/security.module';

import { AuthThrottlerGuard } from './common/security/guards/auth-throttler.guard';
import { FreshAccessGuard } from './common/security/guards/fresh-access.guard';
import { JwtAuthGuard } from './common/security/guards/jwt-auth.guard';
import { RolesGuard } from './common/security/guards/roles.guard';

import { RedisThrottlerStorage } from './common/throttle/storage/redis-throttler.storage';

import { HttpLoggingInterceptor } from './common/http/interceptors/http-logging.interceptor';

function resolveThrottlerStorage(config: ConfigService): ThrottlerStorage {
  const redisUrl = String(config.get('THROTTLE_REDIS_URL') ?? '').trim();

  const rawPrefix = String(config.get('THROTTLE_REDIS_PREFIX') ?? 'throttle:');
  const prefix = rawPrefix.trim().replace(/\s+/g, '') || 'throttle:';

  if (!redisUrl) {
    throw new Error('THROTTLE_REDIS_URL is required');
  }

  return new RedisThrottlerStorage(redisUrl, prefix);
}

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: resolveEnvFilePath(),
      validationSchema: envValidationSchema,
    }),
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => {
        const ttl = Number(config.get('THROTTLE_TTL_SEC') ?? 60);
        const limit = Number(config.get('THROTTLE_LIMIT') ?? 100);

        return {
          throttlers: [{ ttl, limit }],
          storage: resolveThrottlerStorage(config),
        };
      },
    }),
    RequestContextModule,
    ScheduleModule.forRoot(),
    LoggerModule,
    PrismaModule,
    AuthModule,
    UsersModule,
    JobsModule,
    SecurityModule,
  ],
  providers: [
    { provide: APP_GUARD, useClass: AuthThrottlerGuard },
    { provide: APP_GUARD, useClass: JwtAuthGuard },
    { provide: APP_GUARD, useClass: RolesGuard },
    { provide: APP_GUARD, useClass: FreshAccessGuard },
    { provide: APP_INTERCEPTOR, useClass: HttpLoggingInterceptor },
    { provide: APP_FILTER, useClass: GlobalExceptionFilter },
  ],
})
export class AppModule {}
