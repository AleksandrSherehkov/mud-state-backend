import { ForbiddenException, Injectable } from '@nestjs/common';
import type { Request } from 'express';
import { timingSafeEqual } from 'node:crypto';
import { getCookieString } from 'src/common/http/cookies';
import { SecurityPolicyService } from '../policy/security-policy.service';

@Injectable()
export class DoubleSubmitCsrfService {
  constructor(private readonly policy: SecurityPolicyService) {}

  assertValid(req: Request): boolean {
    const p = this.policy.get().csrf;

    const csrfCookie = getCookieString(req, p.cookieName);
    const csrfHeader = req.header(p.headerName);

    const ok =
      Boolean(csrfCookie && csrfHeader) &&
      this.timingSafeEqualString(csrfCookie!, csrfHeader!);

    if (!ok) throw new ForbiddenException('CSRF validation failed');

    return true;
  }

  private timingSafeEqualString(expected: string, provided: string): boolean {
    const a = Buffer.from(expected, 'utf8');
    const b = Buffer.from(provided, 'utf8');

    if (a.length !== b.length) {
      const dummy = Buffer.alloc(a.length);
      b.copy(dummy, 0, 0, Math.min(b.length, a.length));
      timingSafeEqual(a, dummy);
      return false;
    }

    return timingSafeEqual(a, b);
  }
}
