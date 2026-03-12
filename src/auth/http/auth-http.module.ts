import { Module } from '@nestjs/common';

import { AuthCoreModule } from '../core/auth-core.module';

import { AuthController } from '../auth.controller';
import { AuthHttpService } from '../auth-http.service';
import { AuthCookieService } from '../auth-cookie.service';
import { RefreshTokenRequestService } from 'src/common/http/refresh-token';

@Module({
  imports: [AuthCoreModule],
  controllers: [AuthController],
  providers: [AuthCookieService, AuthHttpService, RefreshTokenRequestService],
})
export class AuthHttpModule {}
