import { UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { Role } from '@prisma/client';

import { TokenService } from './token.service';
import type { JwtPayload } from './types/jwt.types';
import type { StringValue } from 'ms';
import { AppLogger } from 'src/logger/logger.service';

describe('TokenService', () => {
  let jwt: jest.Mocked<Pick<JwtService, 'signAsync' | 'verifyAsync'>>;
  let config: jest.Mocked<Pick<ConfigService, 'get'>>;
  let logger: jest.Mocked<
    Pick<
      AppLogger,
      'setContext' | 'log' | 'warn' | 'error' | 'debug' | 'verbose' | 'silly'
    >
  >;

  let service: TokenService;

  beforeEach(() => {
    jwt = {
      signAsync: jest.fn(),
      verifyAsync: jest.fn(),
    };

    config = {
      get: jest.fn(),
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

    service = new TokenService(
      jwt as unknown as JwtService,
      config as unknown as ConfigService,
      logger as unknown as AppLogger,
    );

    expect(logger.setContext).toHaveBeenCalledWith('TokenService');
  });
  describe('hashRefreshToken', () => {
    it('returns deterministic HMAC-SHA256 hex (64 chars) using REFRESH_TOKEN_PEPPER', () => {
      config.get.mockImplementation((key: string) => {
        if (key === 'REFRESH_TOKEN_PEPPER') return 'pepper123';
        return undefined;
      });

      const h1 = service.hashRefreshToken('tokenA');
      const h2 = service.hashRefreshToken('tokenA');

      expect(h1).toBe(h2);
      expect(h1).toHaveLength(64);
    });

    it('throws when REFRESH_TOKEN_PEPPER is missing', () => {
      config.get.mockImplementation(() => undefined);

      expect(() => service.hashRefreshToken('tokenA')).toThrow(
        /REFRESH_TOKEN_PEPPER/i,
      );

      expect(logger.error).toHaveBeenCalled();
    });
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
        if (key === 'JWT_ISSUER') return 'mud-state-backend';
        if (key === 'JWT_AUDIENCE') return 'mud-state-clients';
        return defaultValue as any;
      });

      jwt.signAsync.mockResolvedValue('access-signed');

      const token = await service.signAccessToken(payload);

      expect(jwt.signAsync).toHaveBeenCalledWith(payload, {
        secret: 'secretA',
        expiresIn: '10m',
        issuer: 'mud-state-backend',
        audience: 'mud-state-clients',
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
        if (key === 'JWT_ISSUER') return 'mud-state-backend';
        if (key === 'JWT_AUDIENCE') return 'mud-state-clients';
        return defaultValue as any;
      });

      jwt.signAsync.mockResolvedValue('access-signed');

      const token = await service.signAccessToken(payload);

      expect(jwt.signAsync).toHaveBeenCalledWith(payload, {
        secret: 'secretA',
        expiresIn: '15m',
        issuer: 'mud-state-backend',
        audience: 'mud-state-clients',
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
        if (key === 'JWT_ISSUER') return 'mud-state-backend';
        if (key === 'JWT_AUDIENCE') return 'mud-state-clients';
        return defaultValue as any;
      });

      jwt.signAsync.mockResolvedValue('refresh-signed');

      const token = await service.signRefreshToken(payload);

      expect(jwt.signAsync).toHaveBeenCalledWith(payload, {
        secret: 'secretR',
        expiresIn: '30d',
        issuer: 'mud-state-backend',
        audience: 'mud-state-clients',
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
        if (key === 'JWT_ISSUER') return 'mud-state-backend';
        if (key === 'JWT_AUDIENCE') return 'mud-state-clients';
        return defaultValue as any;
      });

      jwt.signAsync.mockResolvedValue('refresh-signed');

      const token = await service.signRefreshToken(payload);

      expect(jwt.signAsync).toHaveBeenCalledWith(payload, {
        secret: 'secretR',
        expiresIn: '7d',
        issuer: 'mud-state-backend',
        audience: 'mud-state-clients',
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
        if (key === 'JWT_ISSUER') return 'mud-state-backend';
        if (key === 'JWT_AUDIENCE') return 'mud-state-clients';
        return undefined;
      });

      jwt.verifyAsync.mockResolvedValue(payload);

      const result = await service.verifyRefreshToken('token');

      expect(jwt.verifyAsync).toHaveBeenCalledWith('token', {
        secret: 'secR',
        issuer: 'mud-state-backend',
        audience: 'mud-state-clients',
      });
      expect(result).toEqual(payload);
    });

    it('throws UnauthorizedException when verification fails and logs warn', async () => {
      config.get.mockImplementation((key: string) => {
        if (key === 'JWT_REFRESH_SECRET') return 'secR';
        if (key === 'JWT_ISSUER') return 'mud-state-backend';
        if (key === 'JWT_AUDIENCE') return 'mud-state-clients';
        return undefined;
      });

      jwt.verifyAsync.mockRejectedValue(new Error('jwt expired'));

      await expect(service.verifyRefreshToken('bad')).rejects.toThrow(
        new UnauthorizedException('Недійсний refresh токен'),
      );

      expect(logger.warn).toHaveBeenCalled();
    });
  });
});
