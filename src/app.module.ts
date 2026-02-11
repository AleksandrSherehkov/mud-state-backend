import { Module } from '@nestjs/common';

import { ThrottlerModule } from '@nestjs/throttler';

import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { ConfigModule, ConfigService } from '@nestjs/config';

import { ScheduleModule } from '@nestjs/schedule';
import { LoggerModule } from './logger/logger.module';
import { APP_FILTER, APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { HttpLoggingInterceptor } from './common/interceptors/http-logging.interceptor';
import { GlobalExceptionFilter } from './common/filters/global-exception.filter';
import { RequestContextModule } from './common/request-context/request-context.module';
import { JobsModule } from './jobs/jobs.module';
import { AuthThrottlerGuard } from './common/guards/auth-throttler.guard';
import { resolveEnvFilePath } from './config/env-path';
import { envValidationSchema } from './config/env.validation';
import { JwtAuthGuard } from './common/guards/jwt-auth.guard';
import { RolesGuard } from './common/guards/roles.guard';
import { SecurityModule } from './common/security/security.module';
import { BoundedThrottlerStorage } from './common/throttle/bounded-throttler.storage';

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

        const maxKeys = Number(config.get('THROTTLE_STORE_MAX_KEYS') ?? 50_000);
        const cleanupSec = Number(
          config.get('THROTTLE_STORE_CLEANUP_INTERVAL_SEC') ?? 60,
        );

        return {
          throttlers: [{ ttl, limit }],
          storage: new BoundedThrottlerStorage(maxKeys, cleanupSec * 1000),
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
    {
      provide: APP_GUARD,
      useClass: AuthThrottlerGuard,
    },
    {
      provide: APP_GUARD,
      useClass: JwtAuthGuard,
    },
    {
      provide: APP_GUARD,
      useClass: RolesGuard,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: HttpLoggingInterceptor,
    },
    {
      provide: APP_FILTER,
      useClass: GlobalExceptionFilter,
    },
  ],
})
export class AppModule {}
