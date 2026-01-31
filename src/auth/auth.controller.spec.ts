import {
  BadRequestException,
  ConflictException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import type { Request } from 'express';
import {
  Role,
  type RefreshToken,
  type Session,
  type User,
} from '@prisma/client';

import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { SessionService } from '../sessions/session.service';
import { RefreshTokenService } from '../sessions/refresh-token.service';
import { UsersService } from 'src/users/users.service';

import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshDto } from './dto/refresh.dto';
import { TerminateSessionDto } from '../sessions/dto/terminate-session.dto';

import { RegisterResponseDto } from './dto/register-response.dto';
import { LogoutResponseDto } from './dto/logout-response.dto';
import { MeResponseDto } from './dto/me-response.dto';

import type { Tokens } from './types/jwt.types';
import type { UserFromJwt } from './types/user-from-jwt';

jest.mock('src/common/helpers/request-info', () => ({
  extractRequestInfo: jest.fn(),
}));
import { extractRequestInfo } from 'src/common/helpers/request-info';

describe('AuthController', () => {
  let controller: AuthController;

  let authService: jest.Mocked<
    Pick<AuthService, 'register' | 'login' | 'refresh' | 'logout'>
  >;

  let sessionService: jest.Mocked<
    Pick<
      SessionService,
      | 'getActiveUserSessions'
      | 'getAllUserSessions'
      | 'terminateOtherSessions'
      | 'terminateSpecificSession'
    >
  >;

  let refreshTokenService: jest.Mocked<
    Pick<RefreshTokenService, 'getActiveTokens'>
  >;

  let usersService: jest.Mocked<Pick<UsersService, 'findById'>>;

  beforeEach(() => {
    jest.clearAllMocks();

    authService = {
      register: jest.fn(),
      login: jest.fn(),
      refresh: jest.fn(),
      logout: jest.fn(),
    };

    sessionService = {
      getActiveUserSessions: jest.fn(),
      getAllUserSessions: jest.fn(),
      terminateOtherSessions: jest.fn(),
      terminateSpecificSession: jest.fn(),
    };

    refreshTokenService = {
      getActiveTokens: jest.fn(),
    };

    usersService = {
      findById: jest.fn(),
    };

    controller = new AuthController(
      authService as unknown as AuthService,
      sessionService as unknown as SessionService,
      refreshTokenService as unknown as RefreshTokenService,
      usersService as unknown as UsersService,
    );
  });

  const makeUser = (overrides: Partial<User> = {}): User =>
    ({
      id: 'u1',
      email: 'user@example.com',
      password: 'hash',
      role: Role.USER,
      createdAt: new Date('2025-01-01T00:00:00.000Z'),
      characters: [],
      refreshTokens: [],
      sessions: [],
      ...overrides,
    }) as unknown as User;

  describe('register', () => {
    it('extracts ip/userAgent, calls authService.register, returns RegisterResponseDto', async () => {
      const dto: RegisterDto = {
        email: 'new@example.com',
        password: 'secret123',
      };

      const req = {} as unknown as Request;

      (
        extractRequestInfo as jest.MockedFunction<typeof extractRequestInfo>
      ).mockReturnValue({
        ip: '1.2.3.4',
        userAgent: 'TestAgent',
      });

      const serviceResult: ConstructorParameters<
        typeof RegisterResponseDto
      >[0] = {
        id: 'user1',
        email: dto.email,
        role: Role.USER,
        createdAt: new Date('2025-01-02T00:00:00.000Z'),
        accessToken: 'access',
        refreshToken: 'refresh',
        jti: 'jti1',
      };

      authService.register.mockResolvedValue(serviceResult as any);

      const result = await controller.register(dto, req);

      expect(extractRequestInfo).toHaveBeenCalledWith(req);
      expect(authService.register).toHaveBeenCalledWith(
        dto,
        '1.2.3.4',
        'TestAgent',
      );
      expect(result).toEqual(new RegisterResponseDto(serviceResult));
    });
  });

  describe('login', () => {
    it('extracts ip/userAgent, calls authService.login, returns Tokens', async () => {
      const dto: LoginDto = {
        email: 'a@b.c',
        password: 'pw12345',
      };

      const req = {} as unknown as Request;

      (
        extractRequestInfo as jest.MockedFunction<typeof extractRequestInfo>
      ).mockReturnValue({
        ip: '9.9.9.9',
        userAgent: 'UA',
      });

      const tokens: Tokens = {
        accessToken: 'tokenA',
        refreshToken: 'tokenR',
        jti: 'jwtid',
      };

      authService.login.mockResolvedValue(tokens as any);

      const result = await controller.login(dto, req);

      expect(extractRequestInfo).toHaveBeenCalledWith(req);
      expect(authService.login).toHaveBeenCalledWith(dto, '9.9.9.9', 'UA');
      expect(result).toEqual(tokens);
    });
  });

  describe('refresh', () => {
    it('extracts ip/userAgent, calls authService.refresh, returns Tokens', async () => {
      const dto: RefreshDto = {
        refreshToken: 'r1',
      };

      const req = {} as unknown as Request;

      (
        extractRequestInfo as jest.MockedFunction<typeof extractRequestInfo>
      ).mockReturnValue({
        ip: '2.2.2.2',
        userAgent: 'AgentX',
      });

      const tokens: Tokens = {
        accessToken: 'acc',
        refreshToken: 'ref',
        jti: 'j2',
      };

      authService.refresh.mockResolvedValue(tokens as any);

      const result = await controller.refresh(dto, req);

      expect(extractRequestInfo).toHaveBeenCalledWith(req);
      expect(authService.refresh).toHaveBeenCalledWith(
        'r1',
        '2.2.2.2',
        'AgentX',
      );
      expect(result).toEqual(tokens);
    });
  });

  describe('logout', () => {
    it('returns LogoutResponseDto when logout succeeds', async () => {
      const serviceResult: ConstructorParameters<typeof LogoutResponseDto>[0] =
        {
          loggedOut: true,
          terminatedAt: '2025-06-07T11:30:00.000Z',
        };

      authService.logout.mockResolvedValue(serviceResult as any);

      const result = await controller.logout('uid1');

      expect(authService.logout).toHaveBeenCalledWith('uid1');
      expect(result).toEqual(new LogoutResponseDto(serviceResult));
    });

    it('throws BadRequestException when service returns null', async () => {
      authService.logout.mockResolvedValue(null as any);

      await expect(controller.logout('uid2')).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('getMe', () => {
    it('returns MeResponseDto when user exists', async () => {
      const user = makeUser({ id: 'uid3', role: Role.MODERATOR });
      usersService.findById.mockResolvedValue(user);

      const result = await controller.getMe('uid3');

      expect(usersService.findById).toHaveBeenCalledWith('uid3');
      expect(result).toEqual(new MeResponseDto(user));
    });

    it('throws NotFoundException when user does not exist', async () => {
      usersService.findById.mockResolvedValue(null);

      await expect(controller.getMe('missing')).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('getSessions', () => {
    it('maps active refresh tokens to RefreshTokenSessionDto', async () => {
      const createdAt = new Date('2025-03-01T12:00:00.000Z');

      const tokens: Array<
        Pick<RefreshToken, 'jti' | 'ip' | 'userAgent' | 'createdAt'>
      > = [
        { jti: 'j1', ip: '10.0.0.1', userAgent: 'UA1', createdAt },
        { jti: 'j2', ip: null, userAgent: null, createdAt },
      ];

      refreshTokenService.getActiveTokens.mockResolvedValue(tokens as any);

      const result = await controller.getSessions('user1');

      expect(refreshTokenService.getActiveTokens).toHaveBeenCalledWith('user1');
      expect(result).toEqual([
        {
          jti: 'j1',
          ip: '10.0.0.1',
          userAgent: 'UA1',
          createdAt: createdAt.toISOString(),
        },
        {
          jti: 'j2',
          ip: '',
          userAgent: '',
          createdAt: createdAt.toISOString(),
        },
      ]);
    });
  });

  describe('getActiveSessions', () => {
    it('uses default limit=50 when query is missing and maps sessions', async () => {
      const startedAt = new Date('2025-04-01T00:00:00.000Z');

      sessionService.getActiveUserSessions.mockResolvedValue([
        { id: 's1', ip: '1.1.1.1', userAgent: null, startedAt },
      ] as any);

      const result = await controller.getActiveSessions('u1');

      expect(sessionService.getActiveUserSessions).toHaveBeenCalledWith(
        'u1',
        50,
      );
      expect(result).toEqual([
        {
          id: 's1',
          ip: '1.1.1.1',
          userAgent: '',
          startedAt: startedAt.toISOString(),
        },
      ]);
    });

    it('applies limit rules: default=50 for 0/NaN/empty/negative, clamps >100 to 100, keeps valid range', async () => {
      sessionService.getActiveUserSessions.mockResolvedValue([] as any);

      await controller.getActiveSessions('u1', '0');
      expect(sessionService.getActiveUserSessions).toHaveBeenLastCalledWith(
        'u1',
        50,
      );

      await controller.getActiveSessions('u1', '');
      expect(sessionService.getActiveUserSessions).toHaveBeenLastCalledWith(
        'u1',
        50,
      );

      await controller.getActiveSessions('u1', 'abc');
      expect(sessionService.getActiveUserSessions).toHaveBeenLastCalledWith(
        'u1',
        50,
      );

      await controller.getActiveSessions('u1', '-5');
      expect(sessionService.getActiveUserSessions).toHaveBeenLastCalledWith(
        'u1',
        50,
      );

      await controller.getActiveSessions('u1', '200');
      expect(sessionService.getActiveUserSessions).toHaveBeenLastCalledWith(
        'u1',
        100,
      );

      await controller.getActiveSessions('u1', '25');
      expect(sessionService.getActiveUserSessions).toHaveBeenLastCalledWith(
        'u1',
        25,
      );
    });
  });

  describe('terminateOtherSessions', () => {
    it('throws UnauthorizedException when CurrentUser is undefined', async () => {
      await expect(
        controller.terminateOtherSessions(undefined),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('throws ConflictException when no other sessions terminated', async () => {
      sessionService.terminateOtherSessions.mockResolvedValue({
        count: 0,
      } as any);

      const user: UserFromJwt = {
        userId: 'u5',
        email: 'u5@example.com',
        role: Role.USER,
        sid: 'sid1',
      };

      await expect(controller.terminateOtherSessions(user)).rejects.toThrow(
        ConflictException,
      );

      expect(sessionService.terminateOtherSessions).toHaveBeenCalledWith(
        'u5',
        'sid1',
      );
    });

    it('returns terminatedCount when sessions terminated', async () => {
      sessionService.terminateOtherSessions.mockResolvedValue({
        count: 3,
      } as any);

      const user: UserFromJwt = {
        userId: 'u6',
        email: 'u6@example.com',
        role: Role.USER,
        sid: 'sid2',
      };

      const result = await controller.terminateOtherSessions(user);

      expect(sessionService.terminateOtherSessions).toHaveBeenCalledWith(
        'u6',
        'sid2',
      );
      expect(result).toEqual({ terminatedCount: 3 });
    });
  });

  describe('getMySessions', () => {
    it('maps sessions to FullSessionDto shape', async () => {
      const startedAt = new Date('2025-05-01T08:00:00.000Z');
      const endedAt = new Date('2025-05-01T09:00:00.000Z');

      const sessions: Array<
        Pick<
          Session,
          'id' | 'ip' | 'userAgent' | 'isActive' | 'startedAt' | 'endedAt'
        >
      > = [
        {
          id: 'sess1',
          ip: '3.3.3.3',
          userAgent: 'UA3',
          isActive: true,
          startedAt,
          endedAt: null,
        },
        {
          id: 'sess2',
          ip: null,
          userAgent: null,
          isActive: false,
          startedAt,
          endedAt,
        },
      ];

      sessionService.getAllUserSessions.mockResolvedValue(sessions as any);

      const result = await controller.getMySessions('u7');

      expect(sessionService.getAllUserSessions).toHaveBeenCalledWith('u7');
      expect(result).toEqual([
        {
          id: 'sess1',
          ip: '3.3.3.3',
          userAgent: 'UA3',
          isActive: true,
          startedAt: startedAt.toISOString(),
          endedAt: null,
        },
        {
          id: 'sess2',
          ip: '',
          userAgent: '',
          isActive: false,
          startedAt: startedAt.toISOString(),
          endedAt: endedAt.toISOString(),
        },
      ]);
    });
  });

  describe('terminateSpecificSession', () => {
    it('returns terminated=true when count>0', async () => {
      sessionService.terminateSpecificSession.mockResolvedValue({
        count: 1,
      } as any);

      const dto: TerminateSessionDto = {
        ip: '4.4.4.4',
        userAgent: 'UA4',
      };

      const result = await controller.terminateSpecificSession('u8', dto);

      expect(sessionService.terminateSpecificSession).toHaveBeenCalledWith(
        'u8',
        '4.4.4.4',
        'UA4',
      );
      expect(result).toEqual({ terminated: true });
    });

    it('returns terminated=false when count=0', async () => {
      sessionService.terminateSpecificSession.mockResolvedValue({
        count: 0,
      } as any);

      const dto: TerminateSessionDto = {
        ip: '5.5.5.5',
        userAgent: 'UA5',
      };

      const result = await controller.terminateSpecificSession('u9', dto);

      expect(sessionService.terminateSpecificSession).toHaveBeenCalledWith(
        'u9',
        '5.5.5.5',
        'UA5',
      );
      expect(result).toEqual({ terminated: false });
    });
  });
});
