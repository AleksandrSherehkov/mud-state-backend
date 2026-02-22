import { Module } from '@nestjs/common';

import { AuthCoreModule } from './core/auth-core.module';
import { AuthHttpModule } from './http/auth-http.module';

@Module({
  imports: [AuthCoreModule, AuthHttpModule],
  exports: [AuthCoreModule],
})
export class AuthModule {}
