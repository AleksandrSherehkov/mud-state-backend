import { UnauthorizedException } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import { Role } from '@prisma/client';

import { JwtStrategy } from './jwt.strategy';
import type { SessionService } from '../../sessions/session.service';
import type { UsersService } from 'src/users/users.service';
import type { AppLogger } from 'src/logger/logger.service';
import type { JwtPayload } from '../types/jwt.types';

describe('JwtStrategy', () => {
  const configMock: Pick<ConfigService, 'get'> = {
    get: jest.fn((key: string) => {
      if (key === 'JWT_ACCESS_SECRET') return 'test-access-secret';
      return undefined;
    }),
  };

  const sessionServiceMock: jest.Mocked<
    Pick<SessionService, 'isSessionActive'>
  > = {
    isSessionActive: jest.fn(),
  };

  const usersServiceMock: jest.Mocked<
    Pick<UsersService, 'getAuthSnapshotById'>
  > = {
    getAuthSnapshotById: jest.fn(),
  };

  const loggerMock: jest.Mocked<
    Pick<AppLogger, 'setContext' | 'warn' | 'debug' | 'log' | 'error'>
  > = {
    setContext: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
    log: jest.fn(),
    error: jest.fn<
      ReturnType<AppLogger['error']>,
      Parameters<AppLogger['error']>
    >(),
  };

  function makeStrategy() {
    return new JwtStrategy(
      configMock as unknown as ConfigService,
      sessionServiceMock as unknown as SessionService,
      usersServiceMock as unknown as UsersService,
      loggerMock as unknown as AppLogger,
    );
  }

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('rejects: missing sub or sid', async () => {
    const strategy = makeStrategy();
    const payload = { sub: '', sid: '' } as unknown as JwtPayload;

    await expect(strategy.validate(payload)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );

    expect(loggerMock.warn).toHaveBeenCalledWith(
      expect.any(String),
      JwtStrategy.name,
      expect.objectContaining({
        event: 'auth.access.reject',
        reason: 'missing_sub_or_sid',
        userId: '',
        sid: '',
      }),
    );

    expect(sessionServiceMock.isSessionActive).not.toHaveBeenCalled();
    expect(usersServiceMock.getAuthSnapshotById).not.toHaveBeenCalled();
  });

  it('rejects: session inactive', async () => {
    const strategy = makeStrategy();
    sessionServiceMock.isSessionActive.mockResolvedValue(false);

    const payload: JwtPayload = {
      sub: 'user-1',
      sid: 'sid-1',
      email: 'x@x',
      role: Role.ADMIN,
      jti: 'jti-1',
    };

    await expect(strategy.validate(payload)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );

    expect(sessionServiceMock.isSessionActive).toHaveBeenCalledWith(
      'sid-1',
      'user-1',
    );

    expect(loggerMock.warn).toHaveBeenCalledWith(
      expect.any(String),
      JwtStrategy.name,
      expect.objectContaining({
        event: 'auth.access.reject',
        reason: 'session_inactive',
        userId: 'user-1',
        sid: 'sid-1',
      }),
    );

    expect(usersServiceMock.getAuthSnapshotById).not.toHaveBeenCalled();
  });

  it('rejects: user snapshot not found', async () => {
    const strategy = makeStrategy();
    sessionServiceMock.isSessionActive.mockResolvedValue(true);
    usersServiceMock.getAuthSnapshotById.mockResolvedValue(null);

    const payload: JwtPayload = {
      sub: 'user-1',
      sid: 'sid-1',
      email: 'x@x',
      role: Role.ADMIN,
      jti: 'jti-1',
    };

    await expect(strategy.validate(payload)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );

    expect(usersServiceMock.getAuthSnapshotById).toHaveBeenCalledWith('user-1');

    expect(loggerMock.warn).toHaveBeenCalledWith(
      expect.any(String),
      JwtStrategy.name,
      expect.objectContaining({
        event: 'auth.access.reject',
        reason: 'user_not_found',
        userId: 'user-1',
        sid: 'sid-1',
      }),
    );
  });

  it('accepts: returns auth user from DB snapshot (DB wins) and logs mismatch', async () => {
    const strategy = makeStrategy();
    sessionServiceMock.isSessionActive.mockResolvedValue(true);

    usersServiceMock.getAuthSnapshotById.mockResolvedValue({
      id: 'user-1',
      email: 'db@e2e.local',
      role: Role.USER,
    });

    const payload: JwtPayload = {
      sub: 'user-1',
      sid: 'sid-1',
      email: 'token@e2e.local',
      role: Role.ADMIN,
      jti: 'jti-1',
    };

    const res = await strategy.validate(payload);

    expect(res).toEqual({
      userId: 'user-1',
      email: 'db@e2e.local',
      role: Role.USER,
      sid: 'sid-1',
    });

    expect(loggerMock.warn).toHaveBeenCalledWith(
      expect.any(String),
      JwtStrategy.name,
      expect.objectContaining({
        event: 'auth.access.role_mismatch',
        userId: 'user-1',
        sid: 'sid-1',
        tokenRole: Role.ADMIN,
        dbRole: Role.USER,
      }),
    );
  });

  it('accepts: when token role equals DB role (no mismatch log required)', async () => {
    const strategy = makeStrategy();
    sessionServiceMock.isSessionActive.mockResolvedValue(true);

    usersServiceMock.getAuthSnapshotById.mockResolvedValue({
      id: 'user-1',
      email: 'db@e2e.local',
      role: Role.ADMIN,
    });

    const payload: JwtPayload = {
      sub: 'user-1',
      sid: 'sid-1',
      email: 'token@e2e.local',
      role: Role.ADMIN,
      jti: 'jti-1',
    };

    const res = await strategy.validate(payload);

    expect(res).toEqual({
      userId: 'user-1',
      email: 'db@e2e.local',
      role: Role.ADMIN,
      sid: 'sid-1',
    });
  });
});
