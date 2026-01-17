import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { Request } from 'express';
import { UserFromJwt } from '../types/user-from-jwt';
export const CurrentUser = createParamDecorator(
  (
    data: keyof UserFromJwt | undefined,
    ctx: ExecutionContext,
  ): UserFromJwt[keyof UserFromJwt] | UserFromJwt | undefined => {
    const request = ctx.switchToHttp().getRequest<Request>();
    const user = request.user;

    return data ? user?.[data] : user;
  },
);
