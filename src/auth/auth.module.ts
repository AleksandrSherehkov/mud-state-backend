import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import type { StringValue } from 'ms';

import { JwtStrategy } from './strategies/jwt.strategy';
import { PrismaModule } from 'src/prisma/prisma.module';
import { LoggerModule } from 'src/logger/logger.module';
import { ValidatorsModule } from 'src/common/security/validators/validators.module';

import { SessionsModule } from 'src/sessions/sessions.module';
import { UsersModule } from 'src/users/users.module';

import { JwtTokenService } from './jwtTokenService';
import { AuthSecurityService } from './auth-security.service';
import { AuthMaintenanceService } from './auth-maintenance.service';
import { AuthTransactionService } from './auth-transaction.service';
import { AuthCookieService } from './auth-cookie.service';
import { AuthHttpService } from './auth-http.service';
import { AuthTokensService } from './auth-tokens.service';

import { CsrfGuard } from 'src/common/security/guards/csrf.guard';

import { RegisterUseCase } from './use-cases/register.use-case';
import { LoginUseCase } from './use-cases/login.use-case';
import { RefreshUseCase } from './use-cases/refresh.use-case';
import { LogoutUseCase } from './use-cases/logout.use-case';
import { GetMeUseCase } from './use-cases/get-me.use-case';
import { RefreshVerifier } from './use-cases/refresh/refresh.verifier';
import { RefreshRotationService } from './use-cases/refresh/refresh.rotation.service';
import { RefreshIncidentResponseService } from './use-cases/refresh/refresh.incident-response.service';

@Module({
  imports: [
    PrismaModule,
    LoggerModule,
    ValidatorsModule,
    SessionsModule,
    UsersModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('JWT_ACCESS_SECRET'),
        signOptions: {
          expiresIn: config.get<StringValue>(
            'JWT_ACCESS_EXPIRES_IN',
            '15m' as StringValue,
          ),
        },
      }),
    }),
  ],
  providers: [
    AuthTransactionService,
    AuthSecurityService,
    AuthMaintenanceService,
    JwtStrategy,
    JwtTokenService,
    CsrfGuard,
    AuthCookieService,
    AuthTokensService,

    RegisterUseCase,
    LoginUseCase,
    RefreshUseCase,
    RefreshVerifier,
    RefreshRotationService,
    RefreshIncidentResponseService,
    LogoutUseCase,
    GetMeUseCase,

    AuthHttpService,
  ],
  exports: [AuthMaintenanceService, AuthTokensService],
  controllers: [AuthController],
})
export class AuthModule {}
