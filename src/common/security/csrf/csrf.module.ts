import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import { SecurityPolicyService } from '../policy/security-policy.service';

import { RedisNonceStoreService } from './redis-nonce-store.service';
import { OriginPolicyService } from './origin-policy.service';
import { FetchSitePolicyService } from './fetch-site-policy.service';
import { DoubleSubmitCsrfService } from './double-submit.service';
import { CsrfM2mHmacService } from './m2m-hmac.service';
import { CsrfM2mReplayService } from './m2m-replay.service';
import { CsrfValidationService } from './csrf-validation.service';

@Module({
  imports: [ConfigModule],
  providers: [
    CsrfValidationService,
    RedisNonceStoreService,
    OriginPolicyService,
    FetchSitePolicyService,
    DoubleSubmitCsrfService,
    CsrfM2mHmacService,
    CsrfM2mReplayService,
  ],
  exports: [
    CsrfValidationService,
    RedisNonceStoreService,
    OriginPolicyService,
    FetchSitePolicyService,
    DoubleSubmitCsrfService,
    CsrfM2mHmacService,
    CsrfM2mReplayService,
  ],
})
export class CsrfModule {}
