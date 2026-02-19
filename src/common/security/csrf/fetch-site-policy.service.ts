import { ForbiddenException, Injectable } from '@nestjs/common';
import type { Request } from 'express';

import { SecurityPolicyService } from '../policy/security-policy.service';
import type { FetchSiteValue } from '../policy/security-policy.types';

function isFetchSiteValue(v: string): v is FetchSiteValue {
  return v === 'same-origin' || v === 'same-site';
}

@Injectable()
export class FetchSitePolicyService {
  constructor(private readonly policy: SecurityPolicyService) {}

  assertAllowedIfPresent(req: Request): void {
    const p = this.policy.get().csrf;
    const vRaw = (req.header('sec-fetch-site') || '').toLowerCase().trim();
    if (!vRaw) return;

    if (!isFetchSiteValue(vRaw) || !p.allowedFetchSites.includes(vRaw)) {
      throw new ForbiddenException('CSRF validation failed (fetch_site)');
    }
  }

  assertAllowedWhenOnlySignal(req: Request): void {
    const p = this.policy.get().csrf;
    const vRaw = (req.header('sec-fetch-site') || '').toLowerCase().trim();
    if (!vRaw) return;

    if (!isFetchSiteValue(vRaw) || !p.allowedFetchSites.includes(vRaw)) {
      throw new ForbiddenException('CSRF validation failed (fetch_site_only)');
    }
  }
}
