import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from '../users/users.module';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtStrategy } from './strategies/jwt.strategy';
import { PrismaModule } from 'src/prisma/prisma.module';
import { TokenService } from './token.service';
import { RefreshTokenService } from './refresh-token.service';
import { SessionService } from './session.service';
import { LoggerModule } from 'src/logger/logger.module';
import type { StringValue } from 'ms';
import { AuthSecurityService } from './auth-security.service';
import { ValidatorsModule } from 'src/common/validators/validators.module';
import { AuthMaintenanceService } from './auth-maintenance.service';

@Module({
  imports: [
    UsersModule,
    PrismaModule,
    LoggerModule,
    ValidatorsModule,
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
    AuthService,
    AuthSecurityService,
    AuthMaintenanceService,
    JwtStrategy,
    TokenService,
    RefreshTokenService,
    SessionService,
  ],
  exports: [AuthService, AuthMaintenanceService],
  controllers: [AuthController],
})
export class AuthModule {}
