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

import type { RegisterDto } from './dto/register.dto';
import type { LoginDto } from './dto/login.dto';
import type { Tokens, JwtPayload } from './types/jwt.types';

jest.mock('src/common/helpers/ip-normalize', () => ({
  normalizeIp: jest.fn(),
}));
import { normalizeIp } from 'src/common/helpers/ip-normalize';

jest.mock('node:crypto', () => ({
  randomUUID: jest.fn(),
}));
import { randomUUID } from 'node:crypto';

describe('AuthService', () => {
  let service: AuthService;

  let usersService: jest.Mocked<
    Pick<UsersService, 'createUser' | 'findByEmail' | 'findById'>
  >;

  let tokenService: jest.Mocked<
    Pick<
      TokenService,
      'signAccessToken' | 'signRefreshToken' | 'verifyRefreshToken'
    >
  >;

  let refreshTokenService: jest.Mocked<
    Pick<RefreshTokenService, 'revokeAll' | 'revokeIfActive'>
  >;

  let sessionService: jest.Mocked<
    Pick<SessionService, 'terminateAll' | 'terminateByRefreshToken'>
  >;

  let prisma: { $transaction: jest.Mock };

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
    };

    refreshTokenService = {
      revokeAll: jest.fn(),
      revokeIfActive: jest.fn(),
    };

    sessionService = {
      terminateAll: jest.fn(),
      terminateByRefreshToken: jest.fn(),
    };

    prisma = {
      $transaction: jest.fn(),
    };

    service = new AuthService(
      usersService as unknown as UsersService,
      tokenService as unknown as TokenService,
      refreshTokenService as unknown as RefreshTokenService,
      sessionService as unknown as SessionService,
      prisma as unknown as PrismaService,
    );
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
    });

    it('throws UnauthorizedException when password invalid', async () => {
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

      expect(bcrypt.compare).toHaveBeenCalledWith(dto.password, 'hash');
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
      expect(bcrypt.compare).toHaveBeenCalledWith(dto.password, 'hash');

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
        service.refresh(userId, refreshToken, ip, userAgent),
      ).rejects.toThrow(new UnauthorizedException('Недійсний токен'));
    });

    it('throws UnauthorizedException when userId mismatch', async () => {
      tokenService.verifyRefreshToken.mockResolvedValue({
        ...payload,
        sub: 'other',
      } as any);

      await expect(
        service.refresh(userId, refreshToken, ip, userAgent),
      ).rejects.toThrow(
        new UnauthorizedException('Невідповідність користувача'),
      );
    });

    it('throws UnauthorizedException when revokeIfActive returns count=0', async () => {
      tokenService.verifyRefreshToken.mockResolvedValue(payload as any);
      refreshTokenService.revokeIfActive.mockResolvedValue({ count: 0 } as any);

      await expect(
        service.refresh(userId, refreshToken, ip, userAgent),
      ).rejects.toThrow(
        new UnauthorizedException('Токен відкликано або недійсний'),
      );
    });

    it('terminates session by refreshToken jti and issues new tokens', async () => {
      tokenService.verifyRefreshToken.mockResolvedValue(payload as any);
      refreshTokenService.revokeIfActive.mockResolvedValue({ count: 1 } as any);
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

      const result = await service.refresh(userId, refreshToken, ip, userAgent);

      expect(tokenService.verifyRefreshToken).toHaveBeenCalledWith(
        refreshToken,
      );
      expect(refreshTokenService.revokeIfActive).toHaveBeenCalledWith(
        payload.jti,
        userId,
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
    });

    it('throws UnauthorizedException when user not found after token claim', async () => {
      tokenService.verifyRefreshToken.mockResolvedValue(payload as any);
      refreshTokenService.revokeIfActive.mockResolvedValue({ count: 1 } as any);
      sessionService.terminateByRefreshToken.mockResolvedValue({
        count: 1,
      } as any);

      usersService.findById.mockResolvedValue(null);

      await expect(
        service.refresh(userId, refreshToken, ip, userAgent),
      ).rejects.toThrow(new UnauthorizedException('Користувача не знайдено'));
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

      jest.useRealTimers();
    });
  });

  describe('issueTokens (private)', () => {
    it('creates refreshToken + session via transaction, signs tokens, returns Tokens', async () => {
      (randomUUID as unknown as jest.Mock).mockReturnValue('uuid-123');
      (normalizeIp as unknown as jest.Mock).mockReturnValue('nip');

      const refreshCreate = jest.fn().mockResolvedValue(undefined);
      const sessionCreate = jest.fn().mockResolvedValue({ id: 'sid-999' });

      prisma.$transaction.mockImplementation(async (cb: any) => {
        const tx = {
          refreshToken: { create: refreshCreate },
          session: { create: sessionCreate },
        };

        return await cb(tx);
      });

      tokenService.signAccessToken.mockResolvedValue('access-signed');
      tokenService.signRefreshToken.mockResolvedValue('refresh-signed');

      const result: Tokens = await (service as any).issueTokens(
        'u1',
        'user@ex.com',
        Role.USER,
        ' 5.5.5.5 ',
        ' TestUA ',
      );

      expect(normalizeIp).toHaveBeenCalledWith(' 5.5.5.5 ');

      expect(refreshCreate).toHaveBeenCalledWith({
        data: {
          userId: 'u1',
          jti: 'uuid-123',
          ip: 'nip',
          userAgent: 'TestUA',
        },
      });

      expect(sessionCreate).toHaveBeenCalledWith({
        data: {
          userId: 'u1',
          refreshTokenId: 'uuid-123',
          ip: 'nip',
          userAgent: 'TestUA',
        },
      });

      expect(tokenService.signAccessToken).toHaveBeenCalledWith({
        sub: 'u1',
        email: 'user@ex.com',
        jti: 'uuid-123',
        role: Role.USER,
        sid: 'sid-999',
      });

      expect(tokenService.signRefreshToken).toHaveBeenCalledWith({
        sub: 'u1',
        email: 'user@ex.com',
        jti: 'uuid-123',
        role: Role.USER,
        sid: 'sid-999',
      });

      expect(result).toEqual({
        accessToken: 'access-signed',
        refreshToken: 'refresh-signed',
        jti: 'uuid-123',
      });
    });
  });
});
