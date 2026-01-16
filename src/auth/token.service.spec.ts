import { UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { Role } from '@prisma/client';

import { TokenService } from './token.service';
import type { JwtPayload } from './types/jwt.types';
import type { StringValue } from 'ms';

describe('TokenService', () => {
  let jwt: jest.Mocked<Pick<JwtService, 'signAsync' | 'verifyAsync'>>;
  let config: jest.Mocked<Pick<ConfigService, 'get'>>;
  let service: TokenService;

  beforeEach(() => {
    jwt = {
      signAsync: jest.fn(),
      verifyAsync: jest.fn(),
    };

    config = {
      get: jest.fn(),
    };

    service = new TokenService(
      jwt as unknown as JwtService,
      config as unknown as ConfigService,
    );
  });

  describe('signAccessToken', () => {
    it('signs payload with access secret and expiry from config', async () => {
      const payload: JwtPayload = {
        sub: 'u1',
        email: 'u1@ex.com',
        role: Role.USER,
        jti: 'jti-1',
        sid: 'sid-1',
      };

      config.get.mockImplementation((key: string, defaultValue?: unknown) => {
        if (key === 'JWT_ACCESS_SECRET') return 'secretA';
        if (key === 'JWT_ACCESS_EXPIRES_IN') return '10m' as StringValue;
        return defaultValue as any;
      });

      jwt.signAsync.mockResolvedValue('access-signed');

      const token = await service.signAccessToken(payload);

      expect(jwt.signAsync).toHaveBeenCalledWith(payload, {
        secret: 'secretA',
        expiresIn: '10m',
      });
      expect(token).toBe('access-signed');
    });

    it('uses default expiry "15m" when JWT_ACCESS_EXPIRES_IN is not set', async () => {
      const payload: JwtPayload = {
        sub: 'u1',
        email: 'u1@ex.com',
        role: Role.USER,
        jti: 'jti-1',
        sid: 'sid-1',
      };

      config.get.mockImplementation((key: string, defaultValue?: unknown) => {
        if (key === 'JWT_ACCESS_SECRET') return 'secretA';
        if (key === 'JWT_ACCESS_EXPIRES_IN') return defaultValue;
        return defaultValue as any;
      });

      jwt.signAsync.mockResolvedValue('access-signed');

      const token = await service.signAccessToken(payload);

      expect(jwt.signAsync).toHaveBeenCalledWith(payload, {
        secret: 'secretA',
        expiresIn: '15m',
      });
      expect(token).toBe('access-signed');
    });
  });

  describe('signRefreshToken', () => {
    it('signs payload with refresh secret and expiry from config', async () => {
      const payload: JwtPayload = {
        sub: 'u2',
        email: 'u2@ex.com',
        role: Role.ADMIN,
        jti: 'jti-2',
        sid: 'sid-2',
      };

      config.get.mockImplementation((key: string, defaultValue?: unknown) => {
        if (key === 'JWT_REFRESH_SECRET') return 'secretR';
        if (key === 'JWT_REFRESH_EXPIRES_IN') return '30d' as StringValue;
        return defaultValue as any;
      });

      jwt.signAsync.mockResolvedValue('refresh-signed');

      const token = await service.signRefreshToken(payload);

      expect(jwt.signAsync).toHaveBeenCalledWith(payload, {
        secret: 'secretR',
        expiresIn: '30d',
      });
      expect(token).toBe('refresh-signed');
    });

    it('uses default expiry "7d" when JWT_REFRESH_EXPIRES_IN is not set', async () => {
      const payload: JwtPayload = {
        sub: 'u2',
        email: 'u2@ex.com',
        role: Role.ADMIN,
        jti: 'jti-2',
        sid: 'sid-2',
      };

      config.get.mockImplementation((key: string, defaultValue?: unknown) => {
        if (key === 'JWT_REFRESH_SECRET') return 'secretR';
        if (key === 'JWT_REFRESH_EXPIRES_IN') return defaultValue;
        return defaultValue as any;
      });

      jwt.signAsync.mockResolvedValue('refresh-signed');

      const token = await service.signRefreshToken(payload);

      expect(jwt.signAsync).toHaveBeenCalledWith(payload, {
        secret: 'secretR',
        expiresIn: '7d',
      });
      expect(token).toBe('refresh-signed');
    });
  });

  describe('verifyRefreshToken', () => {
    it('returns payload when token is valid', async () => {
      const payload: JwtPayload = {
        sub: 'u3',
        email: 'u3@ex.com',
        role: Role.USER,
        jti: 'jti-3',
        sid: 'sid-3',
      };

      config.get.mockImplementation((key: string) => {
        if (key === 'JWT_REFRESH_SECRET') return 'secR';
        return undefined;
      });

      jwt.verifyAsync.mockResolvedValue(payload);

      const result = await service.verifyRefreshToken('token');

      expect(jwt.verifyAsync).toHaveBeenCalledWith('token', { secret: 'secR' });
      expect(result).toEqual(payload);
    });

    it('throws UnauthorizedException when verification fails', async () => {
      config.get.mockImplementation((key: string) => {
        if (key === 'JWT_REFRESH_SECRET') return 'secR';
        return undefined;
      });

      jwt.verifyAsync.mockRejectedValue(new Error('bad token'));

      await expect(service.verifyRefreshToken('bad')).rejects.toThrow(
        new UnauthorizedException('Недійсний refresh токен'),
      );
    });
  });
});
