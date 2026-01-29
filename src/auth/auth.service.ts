import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';

import * as bcrypt from 'bcrypt';
import { Tokens, JwtPayload } from './types/jwt.types';
import { randomUUID } from 'node:crypto';
import { TokenService } from './token.service';
import { RefreshTokenService } from './refresh-token.service';
import { SessionService } from './session.service';
import { Role } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';
import { normalizeIp } from 'src/common/helpers/ip-normalize';
import { AppLogger } from 'src/logger/logger.service';
import { hashId, maskIp } from 'src/common/helpers/log-sanitize';
import { AuthSecurityService } from './auth-security.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly tokenService: TokenService,
    private readonly refreshTokenService: RefreshTokenService,
    private readonly sessionService: SessionService,
    private readonly prisma: PrismaService,
    private readonly logger: AppLogger,
    private readonly authSecurity: AuthSecurityService,
  ) {
    this.logger.setContext(AuthService.name);
  }

  async register(dto: RegisterDto, ip?: string, userAgent?: string) {
    const emailHash = hashId(dto.email.toLowerCase());

    this.logger.log('Register start', AuthService.name, {
      event: 'auth.register.start',
      emailHash,
    });

    const user = await this.usersService.createUser(dto);

    this.logger.log('User registered', AuthService.name, {
      event: 'auth.register.success',
      userId: user.id,
      role: user.role,
      emailHash,
    });

    const tokens = await this.issueTokens(
      user.id,
      user.email,
      user.role,
      ip,
      userAgent,
    );

    return { ...user, ...tokens };
  }

  async login(dto: LoginDto, ip: string, userAgent: string): Promise<Tokens> {
    const emailHash = hashId(dto.email.toLowerCase());

    const user = await this.usersService.findByEmail(dto.email);
    if (!user) {
      this.logger.warn('Login failed: user not found', AuthService.name, {
        event: 'auth.login.fail',
        reason: 'user_not_found',
        emailHash,
      });
      throw new UnauthorizedException('Невірний email або пароль');
    }

    await this.authSecurity.assertNotLocked(user.id);

    const isValid = await bcrypt.compare(dto.password, user.password);
    if (!isValid) {
      return this.authSecurity.onLoginFailed({
        userId: user.id,
        ip,
        userAgent,
      }) as never;
    }

    await this.authSecurity.onLoginSuccess(user.id);

    await Promise.all([
      this.refreshTokenService.revokeAll(user.id),
      this.sessionService.terminateAll(user.id),
    ]);

    this.logger.log('Login success', AuthService.name, {
      event: 'auth.login.success',
      userId: user.id,
      role: user.role,
      emailHash,
    });

    return this.issueTokens(user.id, user.email, user.role, ip, userAgent);
  }

  async refresh(
    userId: string,
    refreshToken: string,
    ip?: string,
    userAgent?: string,
  ): Promise<Tokens> {
    let payload: JwtPayload & { jti: string };

    try {
      payload = await this.tokenService.verifyRefreshToken(refreshToken);
    } catch {
      this.logger.warn(
        'Refresh failed: invalid token signature',
        AuthService.name,
        {
          event: 'auth.refresh.fail',
          reason: 'invalid_token',
          userId,
        },
      );
      throw new UnauthorizedException('Недійсний токен');
    }

    if (payload.sub !== userId) {
      this.logger.warn('Refresh failed: user mismatch', AuthService.name, {
        event: 'auth.refresh.fail',
        reason: 'user_mismatch',
        userId,
        tokenSub: payload.sub,
        jti: payload.jti,
        sid: payload.sid,
      });
      throw new UnauthorizedException('Невідповідність користувача');
    }

    if (!payload.sid) {
      this.logger.warn(
        'Refresh failed: session missing in token',
        AuthService.name,
        {
          event: 'auth.refresh.fail',
          reason: 'missing_sid',
          userId,
          jti: payload.jti,
        },
      );
      throw new UnauthorizedException('Недійсний токен');
    }

    const sessionActive = await this.sessionService.isSessionActive(
      payload.sid,
      userId,
    );
    if (!sessionActive) {
      const nip = ip ? normalizeIp(ip) : null;
      const ua = userAgent?.trim() || null;

      this.logger.warn(
        'Refresh blocked: session is not active',
        AuthService.name,
        {
          event: 'auth.refresh.blocked',
          reason: 'session_inactive',
          userId,
          jti: payload.jti,
          sid: payload.sid,
          ipMasked: nip ? maskIp(nip) : undefined,
          uaHash: ua ? hashId(ua) : undefined,
        },
      );

      throw new UnauthorizedException('Сесію завершено або недійсна');
    }

    const tokenHash = this.tokenService.hashRefreshToken(refreshToken);

    const claim = await this.refreshTokenService.revokeIfActiveByHash(
      payload.jti,
      userId,
      tokenHash,
    );

    if (claim.count === 0) {
      const nip = ip ? normalizeIp(ip) : null;
      const ua = userAgent?.trim() || null;

      this.logger.warn(
        'Refresh reuse detected or token already revoked',
        AuthService.name,
        {
          event: 'auth.refresh.reuse_detected',
          userId,
          jti: payload.jti,
          sid: payload.sid,
          ipMasked: nip ? maskIp(nip) : undefined,
          uaHash: ua ? hashId(ua) : undefined,
        },
      );

      const [revokeRes, terminateRes] = await Promise.all([
        this.refreshTokenService.revokeAll(userId),
        this.sessionService.terminateAll(userId),
      ]);

      this.logger.warn(
        'Refresh reuse response applied (global revoke + terminate)',
        AuthService.name,
        {
          event: 'auth.refresh.reuse_response_applied',
          userId,
          jti: payload.jti,
          sid: payload.sid,
          revokedTokens: revokeRes.count,
          terminatedSessions: terminateRes.count,
        },
      );

      throw new UnauthorizedException('Токен відкликано або недійсний');
    }

    await this.sessionService.terminateByRefreshToken(payload.jti);

    const user = await this.usersService.findById(userId);
    if (!user) {
      this.logger.warn('Refresh failed: user not found', AuthService.name, {
        event: 'auth.refresh.fail',
        reason: 'user_not_found',
        userId,
        jti: payload.jti,
        sid: payload.sid,
      });
      throw new UnauthorizedException('Користувача не знайдено');
    }

    this.logger.log('Refresh success', AuthService.name, {
      event: 'auth.refresh.success',
      userId,
      role: user.role,
      jti: payload.jti,
      sid: payload.sid,
    });

    return this.issueTokens(user.id, user.email, user.role, ip, userAgent);
  }

  async logout(
    userId: string,
  ): Promise<{ loggedOut: true; terminatedAt: string } | null> {
    const user = await this.usersService.findById(userId);
    if (!user) {
      this.logger.warn('Logout failed: user not found', AuthService.name, {
        event: 'auth.logout.fail',
        reason: 'user_not_found',
        userId,
      });
      throw new NotFoundException('Користувача не знайдено');
    }

    const [revokeResult, terminateResult] = await Promise.all([
      this.refreshTokenService.revokeAll(userId),
      this.sessionService.terminateAll(userId),
    ]);

    if (revokeResult.count === 0 && terminateResult.count === 0) {
      this.logger.log(
        'Logout noop (nothing to revoke/terminate)',
        AuthService.name,
        {
          event: 'auth.logout.noop',
          userId,
        },
      );
      return null;
    }

    this.logger.log('Logout success', AuthService.name, {
      event: 'auth.logout.success',
      userId,
      revoked: revokeResult.count,
      terminated: terminateResult.count,
    });

    return { loggedOut: true, terminatedAt: new Date().toISOString() };
  }

  private async issueTokens(
    userId: string,
    email: string,
    role: Role,
    ip?: string,
    userAgent?: string,
  ): Promise<Tokens> {
    const refreshTokenId = randomUUID();
    const sessionId = randomUUID();

    const nip: string | null = ip ? normalizeIp(ip) : null;
    const ua: string | null = userAgent ? userAgent.trim() : null;

    const payload: JwtPayload = {
      sub: userId,
      email,
      jti: refreshTokenId,
      role,
      sid: sessionId,
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.tokenService.signAccessToken(payload),
      this.tokenService.signRefreshToken(payload),
    ]);

    const tokenHash = this.tokenService.hashRefreshToken(refreshToken);

    try {
      await this.prisma.$transaction(async (tx) => {
        await tx.refreshToken.create({
          data: {
            userId,
            jti: refreshTokenId,
            tokenHash,
            ip: nip,
            userAgent: ua,
          },
        });

        await tx.session.create({
          data: {
            id: sessionId,
            userId,
            refreshTokenId,
            ip: nip,
            userAgent: ua,
          },
        });
      });
    } catch (err: unknown) {
      const errorName = err instanceof Error ? err.name : 'UnknownError';
      const errorMessage = err instanceof Error ? err.message : String(err);

      this.logger.error(
        'Tokens issue transaction failed',
        undefined,
        AuthService.name,
        {
          event: 'auth.tokens.issue_failed',
          userId,
          role,
          jti: refreshTokenId,
          sid: sessionId,
          ipMasked: nip ? maskIp(nip) : undefined,
          uaHash: ua ? hashId(ua) : undefined,
          errorName,
          errorMessage,
        },
      );

      throw err;
    }

    this.logger.log('Tokens issued', AuthService.name, {
      event: 'auth.tokens.issued',
      userId,
      role,
      jti: refreshTokenId,
      sid: sessionId,
      ipMasked: nip ? maskIp(nip) : undefined,
      uaHash: ua ? hashId(ua) : undefined,
    });

    return { accessToken, refreshToken, jti: refreshTokenId };
  }
}
