import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';

import { JwtPayload } from '../types/jwt.types';
import { SessionService } from 'src/sessions/session.service';
import { AppLogger } from 'src/logger/logger.service';
import { AuthUsersPort } from '../ports/auth-users.port';
import { AUTH_USERS_PORT } from '../ports/tokens';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    config: ConfigService,
    private readonly sessionService: SessionService,
    @Inject(AUTH_USERS_PORT)
    private readonly usersService: AuthUsersPort,
    private readonly logger: AppLogger,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: config.get<string>('JWT_ACCESS_SECRET')!,
      ignoreExpiration: false,
      issuer: config.get<string>('JWT_ISSUER'),
      audience: config.get<string>('JWT_AUDIENCE'),
      algorithms: ['HS256'],
    });

    this.logger.setContext(JwtStrategy.name);
  }

  async validate(payload: JwtPayload) {
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

    const active = await this.sessionService.isSessionActive(sid, userId);
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
    };
  }
}
