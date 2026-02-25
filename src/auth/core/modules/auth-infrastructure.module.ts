import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import type { StringValue } from 'ms';

import { PrismaModule } from 'src/prisma/prisma.module';
import { LoggerModule } from 'src/logger/logger.module';
import { ValidatorsModule } from 'src/common/security/validators/validators.module';

import { SessionsModule } from 'src/sessions/sessions.module';
import { UsersModule } from 'src/users/users.module';

import { RiskEngineModule } from 'src/common/security/risk-engine/risk-engine.module';
import { SharedRedisModule } from 'src/common/redis/shared-redis.module';

import { JwtStrategy } from '../../strategies/jwt.strategy';

import { JwtTokenService } from '../../jwt-token.service';
import { AuthSecurityService } from '../../auth-security.service';
import { AuthMaintenanceService } from '../../auth-maintenance.service';
import { AuthTransactionService } from '../../auth-transaction.service';
import { AuthTokensService } from '../../auth-tokens.service';
import { AuthChallengeService } from '../../auth-challenge.service';

@Module({
  imports: [
    ConfigModule,
    PrismaModule,
    LoggerModule,
    ValidatorsModule,
    SessionsModule,
    UsersModule,
    RiskEngineModule,
    SharedRedisModule,

    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('JWT_ACCESS_SECRET'),
        signOptions: {
          expiresIn: config.get<StringValue>(
            'JWT_ACCESS_EXPIRES_IN',
            '10m' as StringValue,
          ),
        },
      }),
    }),
  ],
  providers: [
    AuthTransactionService,
    AuthSecurityService,
    AuthMaintenanceService,
    JwtTokenService,
    AuthTokensService,
    AuthChallengeService,
    JwtStrategy,
  ],
  exports: [
    AuthTransactionService,
    AuthSecurityService,
    AuthMaintenanceService,
    JwtTokenService,
    AuthTokensService,
    AuthChallengeService,
    JwtStrategy,

    LoggerModule,

    SessionsModule,
    UsersModule,
    RiskEngineModule,
    SharedRedisModule,
    JwtModule,
  ],
})
export class AuthInfrastructureModule {}
