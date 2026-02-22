import { Module } from '@nestjs/common';

import { AuthCoreModule } from '../core/auth-core.module';

import { AuthController } from '../auth.controller';
import { AuthHttpService } from '../auth-http.service';
import { AuthCookieService } from '../auth-cookie.service';

@Module({
  imports: [AuthCoreModule],
  controllers: [AuthController],
  providers: [AuthCookieService, AuthHttpService],
})
export class AuthHttpModule {}
