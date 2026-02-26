import { Global, Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import { RefreshTokenHashService } from './crypto/refresh-token-hash.service';

import { CsrfModule } from './csrf/csrf.module';
import { CsrfGuard } from './guards/csrf.guard';
import { CsrfIssueGuard } from './guards/csrf-issue.guard';

import { RequestInfoService } from 'src/common/http/request-info';
import { SecurityPolicyService } from './policy/security-policy.service';

@Global()
@Module({
  imports: [ConfigModule, CsrfModule],
  providers: [
    SecurityPolicyService,
    RefreshTokenHashService,
    CsrfGuard,
    CsrfIssueGuard,
    RequestInfoService,
  ],
  exports: [
    SecurityPolicyService,
    RefreshTokenHashService,
    CsrfGuard,
    CsrfIssueGuard,
    CsrfModule,
    RequestInfoService,
  ],
})
export class SecurityModule {}
