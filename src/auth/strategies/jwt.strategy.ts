import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { JwtPayload } from '../types/jwt.types';
import { SessionService } from '../session.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    config: ConfigService,
    private readonly sessionService: SessionService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: config.get<string>('JWT_ACCESS_SECRET')!,
      ignoreExpiration: false,
    });
  }

  async validate(payload: JwtPayload) {
    const userId = payload.sub;
    const sid = payload.sid;

    if (!userId || !sid) {
      throw new UnauthorizedException('Session is missing');
    }

    const active = await this.sessionService.isSessionActive(sid, userId);
    if (!active) {
      throw new UnauthorizedException('Session is not active');
    }

    return {
      userId,
      email: payload.email,
      role: payload.role,
      sid,
    };
  }
}
