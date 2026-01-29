/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */

import { NotFoundException, UnauthorizedException } from '@nestjs/common';
import { Role } from '@prisma/client';

jest.mock('bcrypt', () => ({
  compare: jest.fn(),
}));
import * as bcrypt from 'bcrypt';

import { AuthService } from './auth.service';
import { UsersService } from '../users/users.service';
import { TokenService } from './token.service';
import { RefreshTokenService } from './refresh-token.service';
import { SessionService } from './session.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { AppLogger } from 'src/logger/logger.service';
import { AuthSecurityService } from './auth-security.service';

import type { RegisterDto } from './dto/register.dto';
import type { LoginDto } from './dto/login.dto';
import type { Tokens, JwtPayload } from './types/jwt.types';
import { normalizeIp } from 'src/common/helpers/ip-normalize';
import { randomUUID } from 'node:crypto';

jest.mock('src/common/helpers/log-sanitize', () => ({
  hashId: jest.fn(() => 'email-hash'),
  maskIp: jest.fn(() => 'ip-masked'),
}));

jest.mock('src/common/helpers/ip-normalize', () => ({
  normalizeIp: jest.fn(),
}));

jest.mock('node:crypto', () => {
  const actual = jest.requireActual('node:crypto');
  // eslint-disable-next-line @typescript-eslint/no-unsafe-return
  return {
    ...actual,
    randomUUID: jest.fn(),
  };
});

describe('AuthService', () => {
  let service: AuthService;

  let usersService: jest.Mocked<
    Pick<UsersService, 'createUser' | 'findByEmail' | 'findById'>
  >;

  let tokenService: jest.Mocked<
    Pick<
      TokenService,
      | 'signAccessToken'
      | 'signRefreshToken'
      | 'verifyRefreshToken'
      | 'hashRefreshToken'
    >
  >;

  let refreshTokenService: jest.Mocked<
    Pick<
      RefreshTokenService,
      'create' | 'revokeAll' | 'revokeIfActiveByHash' | 'assertFingerprint'
    >
  >;

  let sessionService: jest.Mocked<
    Pick<
      SessionService,
      'create' | 'terminateAll' | 'terminateByRefreshToken' | 'isSessionActive'
    >
  >;

  let prisma: { $transaction: jest.Mock };

  let logger: jest.Mocked<
    Pick<
      AppLogger,
      'setContext' | 'log' | 'warn' | 'error' | 'debug' | 'verbose' | 'silly'
    >
  >;

  let authSecurity: jest.Mocked<
    Pick<
      AuthSecurityService,
      'assertNotLocked' | 'onLoginFailed' | 'onLoginSuccess'
    >
  >;

  beforeEach(() => {
    jest.clearAllMocks();

    usersService = {
      createUser: jest.fn(),
      findByEmail: jest.fn(),
      findById: jest.fn(),
    };

    tokenService = {
      signAccessToken: jest.fn(),
      signRefreshToken: jest.fn(),
      verifyRefreshToken: jest.fn(),
      hashRefreshToken: jest.fn(),
    };

    refreshTokenService = {
      create: jest.fn(),
      revokeAll: jest.fn(),
      revokeIfActiveByHash: jest.fn(),
      assertFingerprint: jest.fn().mockResolvedValue(undefined),
    };

    sessionService = {
      create: jest.fn(),
      terminateAll: jest.fn(),
      terminateByRefreshToken: jest.fn(),
      isSessionActive: jest.fn(),
    };

    sessionService.isSessionActive.mockResolvedValue(true);
    refreshTokenService.revokeAll.mockResolvedValue({ count: 0 } as any);
    sessionService.terminateAll.mockResolvedValue({ count: 0 } as any);

    prisma = {
      $transaction: jest.fn(),
    };

    logger = {
      setContext: jest.fn(),
      log: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
      debug: jest.fn(),
      verbose: jest.fn(),
      silly: jest.fn(),
    };

    authSecurity = {
      assertNotLocked: jest.fn().mockResolvedValue(undefined),
      onLoginSuccess: jest.fn().mockResolvedValue(undefined),
      onLoginFailed: jest.fn().mockImplementation(() => {
        throw new UnauthorizedException('Невірний email або пароль');
      }),
    };

    service = new AuthService(
      usersService as unknown as UsersService,
      tokenService as unknown as TokenService,
      refreshTokenService as unknown as RefreshTokenService,
      sessionService as unknown as SessionService,
      prisma as unknown as PrismaService,
      logger as unknown as AppLogger,
      authSecurity as unknown as AuthSecurityService,
    );

    expect(logger.setContext).toHaveBeenCalledWith('AuthService');
  });

  describe('register', () => {
    it('creates user, issues tokens, returns merged result', async () => {
      const dto: RegisterDto = { email: 'user@ex.com', password: 'pass123' };

      const createdUser = {
        id: 'u1',
        email: dto.email,
        password: 'hash',
        role: Role.USER,
        createdAt: new Date('2025-01-01T00:00:00.000Z'),
      };

      usersService.createUser.mockResolvedValue(createdUser as any);

      const tokens: Tokens = { accessToken: 'A', refreshToken: 'R', jti: 'J' };
      const issueSpy = jest
        .spyOn(service as any, 'issueTokens')
        .mockResolvedValue(tokens);

      const result = await service.register(dto, '1.1.1.1', 'UA');

      expect(usersService.createUser).toHaveBeenCalledWith(dto);
      expect(issueSpy).toHaveBeenCalledWith(
        createdUser.id,
        createdUser.email,
        createdUser.role,
        '1.1.1.1',
        'UA',
      );
      expect(result).toEqual({ ...createdUser, ...tokens });

      expect(logger.log).toHaveBeenCalled();
    });
  });

  describe('login', () => {
    it('throws UnauthorizedException when user not found', async () => {
      usersService.findByEmail.mockResolvedValue(null);

      const dto: LoginDto = { email: 'missing@ex.com', password: 'pass123' };

      await expect(service.login(dto, '1.1.1.1', 'UA')).rejects.toThrow(
        new UnauthorizedException('Невірний email або пароль'),
      );
      expect(usersService.findByEmail).toHaveBeenCalledWith(dto.email);
      expect(logger.warn).toHaveBeenCalled();
    });

    it('throws UnauthorizedException when password invalid (handled by AuthSecurityService)', async () => {
      const dto: LoginDto = { email: 'user@ex.com', password: 'wrong123' };

      usersService.findByEmail.mockResolvedValue({
        id: 'u1',
        email: dto.email,
        password: 'hash',
        role: Role.USER,
      } as any);

      (bcrypt.compare as unknown as jest.Mock).mockResolvedValue(false);

      await expect(service.login(dto, '2.2.2.2', 'UA')).rejects.toThrow(
        new UnauthorizedException('Невірний email або пароль'),
      );

      expect(authSecurity.assertNotLocked).toHaveBeenCalledWith('u1');
      expect(bcrypt.compare).toHaveBeenCalledWith(dto.password, 'hash');

      expect(authSecurity.onLoginFailed).toHaveBeenCalledWith({
        userId: 'u1',
        ip: '2.2.2.2',
        userAgent: 'UA',
      });
    });

    it('revokes all tokens/sessions and issues new tokens', async () => {
      const dto: LoginDto = { email: 'user@ex.com', password: 'pass123' };

      usersService.findByEmail.mockResolvedValue({
        id: 'u1',
        email: dto.email,
        password: 'hash',
        role: Role.ADMIN,
      } as any);

      (bcrypt.compare as unknown as jest.Mock).mockResolvedValue(true);

      refreshTokenService.revokeAll.mockResolvedValue({ count: 1 } as any);
      sessionService.terminateAll.mockResolvedValue({ count: 1 } as any);

      const tokens: Tokens = { accessToken: 'A', refreshToken: 'R', jti: 'J' };
      const issueSpy = jest
        .spyOn(service as any, 'issueTokens')
        .mockResolvedValue(tokens);

      const result = await service.login(dto, '3.3.3.3', 'Agent');

      expect(usersService.findByEmail).toHaveBeenCalledWith(dto.email);
      expect(authSecurity.assertNotLocked).toHaveBeenCalledWith('u1');

      expect(bcrypt.compare).toHaveBeenCalledWith(dto.password, 'hash');
      expect(authSecurity.onLoginSuccess).toHaveBeenCalledWith('u1');

      expect(refreshTokenService.revokeAll).toHaveBeenCalledWith('u1');
      expect(sessionService.terminateAll).toHaveBeenCalledWith('u1');

      expect(issueSpy).toHaveBeenCalledWith(
        'u1',
        dto.email,
        Role.ADMIN,
        '3.3.3.3',
        'Agent',
      );

      expect(result).toEqual(tokens);
      expect(logger.log).toHaveBeenCalled();
    });
  });

  describe('refresh', () => {
    const userId = 'u1';
    const refreshToken = 'refresh.jwt';
    const ip = '4.4.4.4';
    const userAgent = 'UA';

    const payload: JwtPayload = {
      sub: userId,
      email: 'user@ex.com',
      role: Role.USER,
      jti: 'jti-1',
      sid: 'sid-1',
    };

    it('throws UnauthorizedException when verifyRefreshToken fails', async () => {
      tokenService.verifyRefreshToken.mockRejectedValue(new Error('bad'));

      await expect(
        service.refresh(refreshToken, ip, userAgent),
      ).rejects.toThrow(new UnauthorizedException('Недійсний токен'));

      expect(logger.warn).toHaveBeenCalled();
    });

    it('throws UnauthorizedException when token has no sub', async () => {
      tokenService.verifyRefreshToken.mockResolvedValue({
        ...payload,
        sub: undefined,
      } as any);

      await expect(
        service.refresh(refreshToken, ip, userAgent),
      ).rejects.toThrow(new UnauthorizedException('Недійсний токен'));

      expect(logger.warn).toHaveBeenCalled();
    });

    it('throws UnauthorizedException when session is not active (blocks before claim)', async () => {
      tokenService.verifyRefreshToken.mockResolvedValue(payload as any);
      sessionService.isSessionActive.mockResolvedValue(false);

      await expect(
        service.refresh(refreshToken, ip, userAgent),
      ).rejects.toThrow(
        new UnauthorizedException('Сесію завершено або недійсна'),
      );

      expect(sessionService.isSessionActive).toHaveBeenCalledWith(
        payload.sid,
        userId,
      );
      expect(refreshTokenService.revokeIfActiveByHash).not.toHaveBeenCalled();
      expect(sessionService.terminateByRefreshToken).not.toHaveBeenCalled();
    });

    it('throws UnauthorizedException when revokeIfActiveByHash returns count=0', async () => {
      tokenService.verifyRefreshToken.mockResolvedValue(payload as any);
      sessionService.isSessionActive.mockResolvedValue(true);

      tokenService.hashRefreshToken.mockReturnValue('hash-r');
      refreshTokenService.revokeIfActiveByHash.mockResolvedValue({
        count: 0,
      } as any);

      refreshTokenService.revokeAll.mockResolvedValue({ count: 2 } as any);
      sessionService.terminateAll.mockResolvedValue({ count: 3 } as any);

      await expect(
        service.refresh(refreshToken, ip, userAgent),
      ).rejects.toThrow(
        new UnauthorizedException('Токен відкликано або недійсний'),
      );

      expect(sessionService.isSessionActive).toHaveBeenCalledWith(
        payload.sid,
        userId,
      );

      expect(refreshTokenService.revokeIfActiveByHash).toHaveBeenCalledWith(
        payload.jti,
        userId,
        'hash-r',
      );

      expect(refreshTokenService.revokeAll).toHaveBeenCalledWith(userId);
      expect(sessionService.terminateAll).toHaveBeenCalledWith(userId);

      expect(logger.warn).toHaveBeenCalled();
    });

    it('terminates session by refreshToken jti and issues new tokens', async () => {
      tokenService.verifyRefreshToken.mockResolvedValue(payload as any);
      sessionService.isSessionActive.mockResolvedValue(true);

      tokenService.hashRefreshToken.mockReturnValue('hash-r');
      refreshTokenService.revokeIfActiveByHash.mockResolvedValue({
        count: 1,
      } as any);

      sessionService.terminateByRefreshToken.mockResolvedValue({
        count: 1,
      } as any);

      usersService.findById.mockResolvedValue({
        id: userId,
        email: payload.email,
        role: payload.role,
      } as any);

      const tokens: Tokens = {
        accessToken: 'A2',
        refreshToken: 'R2',
        jti: 'J2',
      };
      const issueSpy = jest
        .spyOn(service as any, 'issueTokens')
        .mockResolvedValue(tokens);

      const result = await service.refresh(refreshToken, ip, userAgent);

      expect(tokenService.verifyRefreshToken).toHaveBeenCalledWith(
        refreshToken,
      );
      expect(sessionService.isSessionActive).toHaveBeenCalledWith(
        payload.sid,
        userId,
      );

      expect(tokenService.hashRefreshToken).toHaveBeenCalledWith(refreshToken);

      expect(refreshTokenService.revokeIfActiveByHash).toHaveBeenCalledWith(
        payload.jti,
        userId,
        'hash-r',
      );

      expect(sessionService.terminateByRefreshToken).toHaveBeenCalledWith(
        payload.jti,
      );
      expect(usersService.findById).toHaveBeenCalledWith(userId);

      expect(issueSpy).toHaveBeenCalledWith(
        userId,
        payload.email,
        payload.role,
        ip,
        userAgent,
      );

      expect(result).toEqual(tokens);
      expect(logger.log).toHaveBeenCalled();
    });

    it('throws UnauthorizedException when user not found after token claim', async () => {
      tokenService.verifyRefreshToken.mockResolvedValue(payload as any);
      sessionService.isSessionActive.mockResolvedValue(true);

      tokenService.hashRefreshToken.mockReturnValue('hash-r');
      refreshTokenService.revokeIfActiveByHash.mockResolvedValue({
        count: 1,
      } as any);

      sessionService.terminateByRefreshToken.mockResolvedValue({
        count: 1,
      } as any);
      usersService.findById.mockResolvedValue(null);

      await expect(
        service.refresh(refreshToken, ip, userAgent),
      ).rejects.toThrow(new UnauthorizedException('Користувача не знайдено'));

      expect(logger.warn).toHaveBeenCalled();
    });
  });

  describe('logout', () => {
    it('throws NotFoundException when user does not exist', async () => {
      usersService.findById.mockResolvedValue(null);

      await expect(service.logout('missing')).rejects.toThrow(
        new NotFoundException('Користувача не знайдено'),
      );
    });

    it('returns null when nothing was revoked/terminated', async () => {
      usersService.findById.mockResolvedValue({ id: 'u1' } as any);
      refreshTokenService.revokeAll.mockResolvedValue({ count: 0 } as any);
      sessionService.terminateAll.mockResolvedValue({ count: 0 } as any);

      const result = await service.logout('u1');

      expect(result).toBeNull();
      expect(logger.log).toHaveBeenCalled();
    });

    it('returns loggedOut=true and terminatedAt when something changed', async () => {
      const fixed = new Date('2025-06-06T12:00:00.000Z');
      jest.useFakeTimers().setSystemTime(fixed);

      usersService.findById.mockResolvedValue({ id: 'u1' } as any);
      refreshTokenService.revokeAll.mockResolvedValue({ count: 1 } as any);
      sessionService.terminateAll.mockResolvedValue({ count: 0 } as any);

      const result = await service.logout('u1');

      expect(result).toEqual({
        loggedOut: true,
        terminatedAt: fixed.toISOString(),
      });

      expect(logger.log).toHaveBeenCalled();

      jest.useRealTimers();
    });
  });

  describe('issueTokens (private)', () => {
    it('creates refreshToken + session via services in transaction, signs tokens, returns Tokens', async () => {
      (randomUUID as unknown as jest.Mock)
        .mockReturnValueOnce('jti-uuid')
        .mockReturnValueOnce('sid-uuid');

      (normalizeIp as unknown as jest.Mock).mockReturnValue('nip');

      // tx можно оставить минимальным - он просто передается в сервисы
      const tx = { refreshToken: {}, session: {} };

      prisma.$transaction.mockImplementation(async (cb: any) => {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-return
        return await cb(tx);
      });

      refreshTokenService.create.mockResolvedValue({} as any);
      sessionService.create.mockResolvedValue({ id: 'sid-uuid' } as any);

      tokenService.signAccessToken.mockResolvedValue('access-signed');
      tokenService.signRefreshToken.mockResolvedValue('refresh-signed');
      tokenService.hashRefreshToken.mockReturnValue('hash-refresh-signed');

      const result: Tokens = await (service as any).issueTokens(
        'u1',
        'user@ex.com',
        Role.USER,
        ' 5.5.5.5 ',
        ' TestUA ',
      );

      expect(normalizeIp).toHaveBeenCalledWith(' 5.5.5.5 ');

      // ✅ теперь проверяем сервисы, а не tx.model.create
      expect(refreshTokenService.create).toHaveBeenCalledWith(
        'u1',
        'jti-uuid',
        'hash-refresh-signed',
        'nip',
        'TestUA',
        tx,
      );

      expect(sessionService.create).toHaveBeenCalledWith(
        'sid-uuid',
        'u1',
        'jti-uuid',
        'nip',
        'TestUA',
        tx,
      );

      expect(tokenService.signAccessToken).toHaveBeenCalledWith({
        sub: 'u1',
        email: 'user@ex.com',
        jti: 'jti-uuid',
        role: Role.USER,
        sid: 'sid-uuid',
      });

      expect(tokenService.signRefreshToken).toHaveBeenCalledWith({
        sub: 'u1',
        email: 'user@ex.com',
        jti: 'jti-uuid',
        role: Role.USER,
        sid: 'sid-uuid',
      });

      expect(tokenService.hashRefreshToken).toHaveBeenCalledWith(
        'refresh-signed',
      );

      expect(result).toEqual({
        accessToken: 'access-signed',
        refreshToken: 'refresh-signed',
        jti: 'jti-uuid',
      });
    });
  });
});
