/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */

import { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RolesGuard } from './roles.guard';
import { Role } from '@prisma/client';
import type { AppLogger } from 'src/logger/logger.service';

describe('RolesGuard', () => {
  let guard: RolesGuard;

  let reflector: {
    getAllAndOverride: jest.Mock;
  };

  let logger: jest.Mocked<Pick<AppLogger, 'setContext' | 'warn'>>;

  const makeContext = (user?: any): ExecutionContext =>
    ({
      getHandler: jest.fn(),
      getClass: jest.fn(),
      switchToHttp: () => ({
        getRequest: () => ({ user }),
      }),
    }) as unknown as ExecutionContext;

  beforeEach(() => {
    jest.clearAllMocks();

    reflector = {
      getAllAndOverride: jest.fn(),
    };

    logger = {
      setContext: jest.fn(),
      warn: jest.fn(),
    };

    guard = new RolesGuard(
      reflector as unknown as Reflector,
      logger as unknown as AppLogger,
    );
  });

  it('sets logger context in constructor', () => {
    expect(logger.setContext).toHaveBeenCalledWith(RolesGuard.name);
  });

  it('allows access when no roles metadata defined', () => {
    reflector.getAllAndOverride.mockReturnValue(undefined);

    const ctx = makeContext({ role: Role.USER });

    const result = guard.canActivate(ctx);

    expect(result).toBe(true);
    expect(logger.warn).not.toHaveBeenCalled();
  });

  it('allows access when roles metadata is empty array', () => {
    reflector.getAllAndOverride.mockReturnValue([]);

    const ctx = makeContext({ role: Role.USER });

    const result = guard.canActivate(ctx);

    expect(result).toBe(true);
    expect(logger.warn).not.toHaveBeenCalled();
  });

  it('denies access when user is missing in request', () => {
    reflector.getAllAndOverride.mockReturnValue([Role.ADMIN]);

    const ctx = makeContext(undefined);

    const result = guard.canActivate(ctx);

    expect(result).toBe(false);

    expect(logger.warn).toHaveBeenCalledWith(
      'Forbidden: missing user in request',
      RolesGuard.name,
      expect.objectContaining({
        event: 'authz.deny',
        reason: 'missing_user',
        requiredRoles: [Role.ADMIN],
      }),
    );
  });

  it('denies access when user role does not match', () => {
    reflector.getAllAndOverride.mockReturnValue([Role.ADMIN]);

    const ctx = makeContext({
      userId: 'u1',
      role: Role.USER,
      sid: 'sid-1',
    });

    const result = guard.canActivate(ctx);

    expect(result).toBe(false);

    expect(logger.warn).toHaveBeenCalledWith(
      'Forbidden: insufficient role',
      RolesGuard.name,
      expect.objectContaining({
        event: 'authz.deny',
        reason: 'role_mismatch',
        requiredRoles: [Role.ADMIN],
        role: Role.USER,
        userId: 'u1',
        sid: 'sid-1',
      }),
    );
  });

  it('allows access when user role matches', () => {
    reflector.getAllAndOverride.mockReturnValue([Role.ADMIN, Role.MODERATOR]);

    const ctx = makeContext({
      userId: 'u2',
      role: Role.ADMIN,
      sid: 'sid-2',
    });

    const result = guard.canActivate(ctx);

    expect(result).toBe(true);
    expect(logger.warn).not.toHaveBeenCalled();
  });
});
