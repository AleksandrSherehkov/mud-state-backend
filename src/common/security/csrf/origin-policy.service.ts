import { ForbiddenException, Injectable } from '@nestjs/common';
import type { Request } from 'express';
import { SecurityPolicyService } from '../policy/security-policy.service';

function parseOriginLike(value: string): string | null {
  try {
    const u = new URL(value);
    return u.origin;
  } catch {
    return null;
  }
}

@Injectable()
export class OriginPolicyService {
  constructor(private readonly policy: SecurityPolicyService) {}

  assertAllowed(req: Request): void {
    const p = this.policy.get().csrf;
    const trusted = p.trustedOrigins;

    const originHeader = req.header('origin') || '';
    const refererHeader = req.header('referer') || '';

    const origin = originHeader ? parseOriginLike(originHeader) : null;
    const refererOrigin = refererHeader ? parseOriginLike(refererHeader) : null;

    const hasSignals = Boolean(origin || refererOrigin);
    if (!hasSignals) return;

    const ok =
      (origin && trusted.includes(origin)) ||
      (refererOrigin && trusted.includes(refererOrigin));

    if (!ok)
      throw new ForbiddenException(
        'CSRF validation failed (origin_not_trusted)',
      );
  }
}
