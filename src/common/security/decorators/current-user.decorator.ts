import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import type { Request } from 'express';
import type { UserFromJwt } from 'src/common/security/types/user-from-jwt';

type AuthRequest = Request & { user?: unknown };

export const CurrentUser = createParamDecorator(
  (data: keyof UserFromJwt | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest<AuthRequest>();
    const user = request.user as UserFromJwt | undefined;

    if (!user) return undefined;
    return data ? user[data] : user;
  },
);
