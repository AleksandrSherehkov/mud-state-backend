import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
import { FRESH_ACCESS_MAX_AGE_SEC_KEY } from 'src/common/decorators/require-fresh-access.decorator';
import type { UserFromJwt } from 'src/common/types/user-from-jwt';

type AuthRequest = Request & { user?: UserFromJwt };

@Injectable()
export class FreshAccessGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const maxAgeSec = this.reflector.getAllAndOverride<number>(
      FRESH_ACCESS_MAX_AGE_SEC_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (!maxAgeSec) return true;

    const req = context.switchToHttp().getRequest<AuthRequest>();

    const iat = typeof req.user?.iat === 'number' ? req.user.iat : undefined;

    if (!iat || !Number.isFinite(iat)) {
      throw new UnauthorizedException('Токен відкликано або недійсний');
    }

    const nowSec = Math.floor(Date.now() / 1000);
    const age = nowSec - iat;

    if (age <= maxAgeSec) return true;

    throw new UnauthorizedException('Токен відкликано або недійсний');
  }
}
