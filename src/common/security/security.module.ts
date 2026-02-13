import { Global, Module } from '@nestjs/common';
import { RefreshTokenHashService } from './crypto/refresh-token-hash.service';

@Global()
@Module({
  providers: [RefreshTokenHashService],
  exports: [RefreshTokenHashService],
})
export class SecurityModule {}
