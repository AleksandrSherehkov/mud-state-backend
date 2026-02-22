import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import type { StringValue } from 'ms';

import { PrismaModule } from 'src/prisma/prisma.module';
import { LoggerModule } from 'src/logger/logger.module';
import { ValidatorsModule } from 'src/common/security/validators/validators.module';

import { SessionsModule } from 'src/sessions/sessions.module';
import { UsersModule } from 'src/users/users.module';

import { JwtStrategy } from '../strategies/jwt.strategy';

import { JwtTokenService } from '../jwtTokenService';
import { AuthSecurityService } from '../auth-security.service';
import { AuthMaintenanceService } from '../auth-maintenance.service';
import { AuthTransactionService } from '../auth-transaction.service';
import { AuthTokensService } from '../auth-tokens.service';
import { AuthChallengeService } from '../auth-challenge.service';

import { RegisterUseCase } from '../use-cases/register.use-case';
import { LoginUseCase } from '../use-cases/login.use-case';
import { RefreshUseCase } from '../use-cases/refresh.use-case';
import { LogoutUseCase } from '../use-cases/logout.use-case';
import { GetMeUseCase } from '../use-cases/get-me.use-case';

import { RefreshVerifier } from '../use-cases/refresh/refresh.verifier';
import { RefreshRotationService } from '../use-cases/refresh/refresh.rotation.service';
import { RefreshIncidentResponseService } from '../use-cases/refresh/refresh.incident-response.service';

@Module({
  imports: [
    ConfigModule,
    PrismaModule,
    LoggerModule,
    ValidatorsModule,
    SessionsModule,
    UsersModule,

    // Token infra lives in Core (reusable), not in HTTP transport.
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
    // infra
    AuthTransactionService,
    AuthSecurityService,
    AuthMaintenanceService,
    JwtTokenService,
    AuthTokensService,
    AuthChallengeService,

    // authn strategy for JwtAuthGuard (passport-jwt)
    JwtStrategy,

    // use-cases
    RegisterUseCase,
    LoginUseCase,
    RefreshUseCase,
    LogoutUseCase,
    GetMeUseCase,

    // refresh internals
    RefreshVerifier,
    RefreshRotationService,
    RefreshIncidentResponseService,
  ],
  exports: [
    // what transport layer needs
    RegisterUseCase,
    LoginUseCase,
    RefreshUseCase,
    LogoutUseCase,
    GetMeUseCase,

    // what other modules might need (as before)
    AuthMaintenanceService,
    AuthTokensService,

    // keep passport strategy visible to the app
    JwtStrategy,
  ],
})
export class AuthCoreModule {}
