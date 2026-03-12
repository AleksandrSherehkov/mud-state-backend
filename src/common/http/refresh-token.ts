import { Injectable } from '@nestjs/common';
import type { Request } from 'express';

import { getCookieString } from 'src/common/http/cookies';
import { SecurityPolicyService } from 'src/common/security/policy/security-policy.service';

@Injectable()
export class RefreshTokenRequestService {
  constructor(private readonly securityPolicy: SecurityPolicyService) {}

  getRefreshTokenFromRequest(req: Request): string | undefined {
    const cookieName = this.securityPolicy.get().auth.refreshCookieName;
    return getCookieString(req, cookieName, { signed: true });
  }
}
