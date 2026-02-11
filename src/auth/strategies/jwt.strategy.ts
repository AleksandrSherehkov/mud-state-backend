import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import type { Request as ExpressRequest } from 'express';

import { JwtPayload } from '../types/jwt.types';
import { SessionsService } from 'src/sessions/sessions.service';
import { AppLogger } from 'src/logger/logger.service';
import { UsersService } from 'src/users/users.service';
import { extractRequestInfo } from 'src/common/helpers/request-info';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    config: ConfigService,
    private readonly sessionsService: SessionsService,
    private readonly usersService: UsersService,
    private readonly logger: AppLogger,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: config.get<string>('JWT_ACCESS_SECRET')!,
      ignoreExpiration: false,
      issuer: config.get<string>('JWT_ISSUER'),
      audience: config.get<string>('JWT_AUDIENCE'),
      algorithms: ['HS256'],
      passReqToCallback: true,
    });

    this.logger.setContext(JwtStrategy.name);
  }

  async validate(
    req: ExpressRequest,
    payload: JwtPayload & { iat?: number; exp?: number },
  ) {
    const userId = payload.sub;
    const sid = payload.sid;

    if (!userId || !sid) {
      this.logger.warn(
        'Access token rejected: missing sub/sid',
        JwtStrategy.name,
        {
          event: 'auth.access.reject',
          reason: 'missing_sub_or_sid',
          userId,
          sid,
        },
      );
      throw new UnauthorizedException('Session is missing');
    }

    const active = await this.sessionsService.isSessionActive(sid, userId);
    if (!active) {
      this.logger.warn(
        'Access token rejected: session inactive',
        JwtStrategy.name,
        {
          event: 'auth.access.reject',
          reason: 'session_inactive',
          userId,
          sid,
        },
      );
      throw new UnauthorizedException('Session is not active');
    }

    const { ip, userAgent, geo } = extractRequestInfo(req);
    await this.sessionsService.assertAccessContext({
      sid,
      userId,
      ip,
      userAgent,
      geo,
    });

    const snap = await this.usersService.getAuthSnapshotById(userId);
    if (!snap) {
      this.logger.warn(
        'Access token rejected: user not found',
        JwtStrategy.name,
        {
          event: 'auth.access.reject',
          reason: 'user_not_found',
          userId,
          sid,
        },
      );
      throw new UnauthorizedException('User not found');
    }

    if (payload.role && payload.role !== snap.role) {
      this.logger.warn(
        'Access token role mismatch (DB wins)',
        JwtStrategy.name,
        {
          event: 'auth.access.role_mismatch',
          userId,
          sid,
          tokenRole: payload.role,
          dbRole: snap.role,
        },
      );
    }

    return {
      userId: snap.id,
      email: snap.email,
      role: snap.role,
      sid,
      iat: payload.iat,
      exp: payload.exp,
    };
  }
}
