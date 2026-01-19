import { Module } from '@nestjs/common';

import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';

import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { ConfigModule, ConfigService } from '@nestjs/config';
import * as Joi from 'joi';
import { ScheduleModule } from '@nestjs/schedule';
import { LoggerModule } from './logger/logger.module';
import { APP_FILTER, APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { HttpLoggingInterceptor } from './common/interceptors/http-logging.interceptor';
import { GlobalExceptionFilter } from './common/filters/global-exception.filter';
import { RequestContextModule } from './common/request-context/request-context.module';
import { JobsModule } from './jobs/jobs.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validationSchema: Joi.object({
        APP_ENV: Joi.string()
          .valid('development', 'production', 'test')
          .default('development'),
        DATABASE_URL: Joi.string().required(),
        API_PREFIX: Joi.string().default('api'),
        API_VERSION: Joi.string().pattern(/^\d+$/).default('1'),
        JWT_ACCESS_SECRET: Joi.string().required(),
        JWT_REFRESH_SECRET: Joi.string().required(),
        PORT: Joi.number().default(3000),
        BASE_URL: Joi.string().uri().default('http://localhost:3000'),
        JWT_ACCESS_EXPIRES_IN: Joi.string().default('15m'),
        JWT_REFRESH_EXPIRES_IN: Joi.string().default('7d'),
        BCRYPT_SALT_ROUNDS: Joi.number().default(10),
        THROTTLE_TTL: Joi.number().default(60),
        THROTTLE_LIMIT: Joi.number().default(10),
        LOG_DIR: Joi.string().default('logs'),
        LOG_FILE_NAME: Joi.string().default('%DATE%.log'),
        LOG_DATE_PATTERN: Joi.string().default('YYYY-MM-DD'),
        LOG_ZIPPED_ARCHIVE: Joi.boolean().default(true),
        LOG_MAX_SIZE: Joi.string().default('10m'),
        LOG_MAX_FILES: Joi.string().default('14d'),
        LOG_LEVEL: Joi.string()
          .valid('error', 'warn', 'info', 'http', 'verbose', 'debug', 'silly')
          .default('debug'),
        PRISMA_LOG_QUERIES: Joi.boolean().default(false),
        PRISMA_QUERY_SAMPLE_RATE: Joi.number().min(0).max(1).default(0.05),
        TOKEN_CLEANUP_DAYS: Joi.number().min(1).max(365).default(7),
        TOKEN_CLEANUP_CRON: Joi.string().default('0 0 * * *'),
        REFRESH_TOKEN_PEPPER: Joi.string().length(64).hex().required(),
      }),
      envFilePath:
        process.env.APP_ENV === 'test' || process.env.NODE_ENV === 'test'
          ? '.env.test'
          : '.env',
    }),
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        throttlers: [
          {
            ttl: Number(config.get('THROTTLE_TTL') ?? 60),
            limit: Number(config.get('THROTTLE_LIMIT') ?? 10),
          },
        ],
      }),
    }),
    RequestContextModule,
    ScheduleModule.forRoot(),
    LoggerModule,
    PrismaModule,
    AuthModule,
    UsersModule,
    JobsModule,
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
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
