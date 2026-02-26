import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import type { Request } from 'express';

import { CsrfValidationService } from '../csrf/csrf-validation.service';

@Injectable()
export class CsrfIssueGuard implements CanActivate {
  constructor(private readonly csrf: CsrfValidationService) {}

  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest<Request>();
    this.csrf.assertCsrfIssuanceAllowed(req);
    return true;
  }
}
