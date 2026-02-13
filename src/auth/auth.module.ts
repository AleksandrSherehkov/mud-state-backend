import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtStrategy } from './strategies/jwt.strategy';
import { PrismaModule } from 'src/prisma/prisma.module';
import { TokenService } from './token.service';
import { LoggerModule } from 'src/logger/logger.module';
import type { StringValue } from 'ms';
import { AuthSecurityService } from './auth-security.service';
import { ValidatorsModule } from 'src/common/security/validators/validators.module';
import { AuthMaintenanceService } from './auth-maintenance.service';
import { AuthTransactionService } from './auth-transaction.service';
import { SessionsModule } from 'src/sessions/sessions.module';
import { UsersModule } from 'src/users/users.module';
import { CsrfGuard } from 'src/common/security/guards/csrf.guard';
import { AuthCookieService } from './auth-cookie.service';
import { AuthHttpService } from './auth-http.service';

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
    AuthService,
    AuthSecurityService,
    AuthMaintenanceService,
    JwtStrategy,
    TokenService,
    CsrfGuard,
    AuthCookieService,
    AuthHttpService,
  ],
  exports: [AuthService, AuthMaintenanceService],
  controllers: [AuthController],
})
export class AuthModule {}
