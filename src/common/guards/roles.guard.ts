import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';
import type { Request } from 'express';
import { Role } from '@prisma/client';
import { AppLogger } from 'src/logger/logger.service';

type RequestUserWithRole = { userId?: string; role: Role; sid?: string };

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly logger: AppLogger,
  ) {
    this.logger.setContext(RolesGuard.name);
  }

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles || requiredRoles.length === 0) return true;

    const request = context.switchToHttp().getRequest<Request>();
    const user = request.user as RequestUserWithRole | undefined;

    if (!user) {
      this.logger.warn('Forbidden: missing user in request', RolesGuard.name, {
        event: 'authz.deny',
        reason: 'missing_user',
        requiredRoles,
      });

      throw new ForbiddenException({
        message: 'Недостатньо прав доступу',
        reason: 'missing_user',
      });
    }

    const allowed = requiredRoles.includes(user.role);

    if (!allowed) {
      this.logger.warn('Forbidden: insufficient role', RolesGuard.name, {
        event: 'authz.deny',
        reason: 'role_mismatch',
        requiredRoles,
        role: user.role,
        userId: user.userId,
        sid: user.sid,
      });

      throw new ForbiddenException({
        message: 'Недостатньо прав доступу',
        reason: 'role_mismatch',
        requiredRoles,
      });
    }

    return true;
  }
}
