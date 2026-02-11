import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';

import * as bcrypt from 'bcrypt';
import { Tokens, JwtPayload } from './types/jwt.types';
import { randomUUID } from 'node:crypto';
import { TokenService } from './token.service';

import { Role } from '@prisma/client';

import { normalizeIp } from 'src/common/helpers/ip-normalize';
import { AppLogger } from 'src/logger/logger.service';
import { hashId, maskIp } from 'src/common/helpers/log-sanitize';
import { AuthSecurityService } from './auth-security.service';
import { AuthTransactionService } from './auth-transaction.service';
import { ConfigService } from '@nestjs/config';
import { UsersService } from 'src/users/users.service';
import { RefreshTokenService } from 'src/sessions/refresh-token.service';
import { SessionsService } from 'src/sessions/sessions.service';
import { SessionLifecycleService } from 'src/sessions/session-lifecycle.service';

@Injectable()
export class AuthService {
  private readonly dummyPasswordHash: string;
  constructor(
    private readonly usersService: UsersService,
    private readonly tokenService: TokenService,
    private readonly refreshTokenService: RefreshTokenService,
    private readonly sessionsService: SessionsService,
    private readonly lifecycle: SessionLifecycleService,
    private readonly tx: AuthTransactionService,
    private readonly logger: AppLogger,
    private readonly authSecurity: AuthSecurityService,
    private readonly config: ConfigService,
  ) {
    this.logger.setContext(AuthService.name);
    this.dummyPasswordHash =
      this.config.get<string>('AUTH_DUMMY_PASSWORD_HASH') ??
      '$2b$12$0IP/zdzyXTrX7AZRHVrTQeVvCAklfEeF8VCj0.9pJqlDmbqgth5Dq';
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
    const nip = ip ? normalizeIp(ip) : 'unknown';
    const ua = userAgent?.trim() || 'unknown';
    const emailHash = hashId(dto.email.toLowerCase());

    const user = await this.usersService.findByEmail(dto.email);
    if (!user) {
      await bcrypt.compare(dto.password, this.dummyPasswordHash);

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
        ip: nip,
        userAgent: ua,
      }) as never;
    }

    await this.authSecurity.onLoginSuccess(user.id);

    this.logger.log('Login success', AuthService.name, {
      event: 'auth.login.success',
      userId: user.id,
      role: user.role,
      emailHash,
    });

    return this.issueTokens(user.id, user.email, user.role, ip, userAgent);
  }

  private static readonly RefreshClaimFailed = class RefreshClaimFailed extends Error {
    constructor() {
      super('refresh_claim_failed');
      this.name = 'RefreshClaimFailed';
    }
  };

  async refresh(
    refreshToken: string,
    ip?: string,
    userAgent?: string,
  ): Promise<Tokens> {
    const payload = await this.verifyRefreshOrThrow(refreshToken);

    const userId = this.requireUserId(payload);
    const sid = this.requireSid(payload, userId);

    await this.assertSessionActiveOrThrow({
      sid,
      userId,
      payload,
      ip,
      userAgent,
    });

    await this.refreshTokenService.assertFingerprint({
      userId,
      jti: payload.jti,
      sid,
      ip: ip ? normalizeIp(ip) : null,
      userAgent: userAgent?.trim() || null,
    });

    const user = await this.getUserOrThrow(userId, payload);

    try {
      return await this.rotateAndIssueTokensAtomic({
        user,
        sid,
        oldJti: payload.jti,
        refreshToken,
        ip,
        userAgent,
      });
    } catch (e: unknown) {
      if (e instanceof AuthService.RefreshClaimFailed) {
        await this.handleRefreshReuseDetected({
          payload,
          userId,
          sid,
          ip,
          userAgent,
        });
      }
      throw e;
    }
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

    const { revokedTokens, terminatedSessions } =
      await this.lifecycle.revokeAllAndTerminateAll({
        userId,
        reason: 'logout',
      });

    if (revokedTokens === 0 && terminatedSessions === 0) {
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
      revoked: revokedTokens,
      terminated: terminatedSessions,
    });

    return { loggedOut: true, terminatedAt: new Date().toISOString() };
  }

  async getMe(userId: string) {
    const user = await this.usersService.findById(userId);
    if (!user) throw new NotFoundException('Користувача не знайдено');
    return user;
  }

  private getMaxActiveSessions(): number {
    const raw = this.config.get<string>('AUTH_MAX_ACTIVE_SESSIONS') ?? '10';
    const n = Number.parseInt(raw, 10);
    if (!Number.isFinite(n)) return 10;
    return Math.min(Math.max(n, 1), 50);
  }
  private async issueTokens(
    userId: string,
    email: string,
    role: Role,
    ip?: string,
    userAgent?: string,
  ): Promise<Tokens> {
    const refreshJti = randomUUID();
    const sessionId = randomUUID();

    const nip: string | null = ip ? normalizeIp(ip) : null;
    const ua: string | null = userAgent ? userAgent.trim() : null;

    const payload: JwtPayload = {
      sub: userId,
      email,
      jti: refreshJti,
      role,
      sid: sessionId,
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.tokenService.signAccessToken(payload),
      this.tokenService.signRefreshToken(payload),
    ]);

    const tokenSalt = this.tokenService.generateRefreshTokenSalt();
    const tokenHash = this.tokenService.hashRefreshToken(
      refreshToken,
      tokenSalt,
    );
    const maxActive = this.getMaxActiveSessions();

    try {
      await this.tx.run(async (tx) => {
        await this.sessionsService.enforceMaxActiveSessions({
          userId,
          maxActive,
          tx,
          meta: {
            event: 'auth.tokens.cap',
            sidNew: sessionId,
            jtiNew: refreshJti,
          },
        });

        await this.refreshTokenService.create(
          userId,
          refreshJti,
          tokenHash,
          tokenSalt,
          nip ?? undefined,
          ua ?? undefined,
          tx,
        );

        await this.sessionsService.create(
          sessionId,
          userId,
          refreshJti,
          nip ?? undefined,
          ua ?? undefined,
          tx,
        );
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
          jti: refreshJti,
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
      jti: refreshJti,
      sid: sessionId,
      ipMasked: nip ? maskIp(nip) : undefined,
      uaHash: ua ? hashId(ua) : undefined,
    });

    return { accessToken, refreshToken, jti: refreshJti };
  }
  private async verifyRefreshOrThrow(
    refreshToken: string,
  ): Promise<JwtPayload> {
    try {
      return await this.tokenService.verifyRefreshToken(refreshToken);
    } catch {
      this.logger.warn(
        'Refresh failed: invalid token signature',
        AuthService.name,
        {
          event: 'auth.refresh.fail',
          reason: 'invalid_token',
        },
      );
      throw new UnauthorizedException('Недійсний токен');
    }
  }

  private requireUserId(payload: JwtPayload): string {
    const userId = payload.sub;

    if (!userId) {
      this.logger.warn(
        'Refresh failed: missing sub in token',
        AuthService.name,
        {
          event: 'auth.refresh.fail',
          reason: 'missing_sub',
          jti: payload.jti,
          sid: payload.sid,
        },
      );
      throw new UnauthorizedException('Недійсний токен');
    }

    return userId;
  }

  private requireSid(payload: JwtPayload, userId: string): string {
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

    return payload.sid;
  }

  private async assertSessionActiveOrThrow(args: {
    sid: string;
    userId: string;
    payload: JwtPayload;
    ip?: string;
    userAgent?: string;
  }): Promise<void> {
    const { sid, userId, payload, ip, userAgent } = args;

    const sessionActive = await this.sessionsService.isSessionActive(
      sid,
      userId,
    );
    if (sessionActive) return;

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
        sid,
        ipMasked: nip ? maskIp(nip) : undefined,
        uaHash: ua ? hashId(ua) : undefined,
      },
    );

    throw new UnauthorizedException('Сесію завершено або недійсна');
  }

  private async rotateAndIssueTokensAtomic(args: {
    user: { id: string; email: string; role: Role };
    sid: string;
    oldJti: string;
    refreshToken: string;
    ip?: string;
    userAgent?: string;
  }): Promise<Tokens> {
    const { user, sid, oldJti, refreshToken, ip, userAgent } = args;

    const nip: string | null = ip ? normalizeIp(ip) : null;
    const ua: string | null = userAgent?.trim() || null;

    const newJti = randomUUID();

    const newPayload: JwtPayload = {
      sub: user.id,
      email: user.email,
      role: user.role,
      sid,
      jti: newJti,
    };

    const [accessToken, newRefreshToken] = await Promise.all([
      this.tokenService.signAccessToken(newPayload),
      this.tokenService.signRefreshToken(newPayload),
    ]);

    const newSalt = this.tokenService.generateRefreshTokenSalt();
    const newTokenHash = this.tokenService.hashRefreshToken(
      newRefreshToken,
      newSalt,
    );

    await this.tx.run(async (tx) => {
      const claim = await this.refreshTokenService.claimRefreshToken(
        { jti: oldJti, userId: user.id, refreshToken },
        tx,
      );

      if (claim.count === 0) {
        throw new AuthService.RefreshClaimFailed();
      }

      await this.refreshTokenService.create(
        user.id,
        newJti,
        newTokenHash,
        newSalt,
        nip ?? undefined,
        ua ?? undefined,
        tx,
      );

      const updatedCount = await this.sessionsService.updateRefreshBinding({
        sid,
        userId: user.id,
        newJti,
        ip: nip,
        userAgent: ua,
        tx,
      });

      if (updatedCount === 0) {
        throw new UnauthorizedException('Сесію завершено або недійсна');
      }
    });

    this.logger.log(
      'Refresh success (atomic claim+rotate+bind)',
      AuthService.name,
      {
        event: 'auth.refresh.success_atomic',
        userId: user.id,
        role: user.role,
        oldJti,
        newJti,
        sid,
      },
    );

    return { accessToken, refreshToken: newRefreshToken, jti: newJti };
  }

  private async handleRefreshReuseDetected(args: {
    payload: JwtPayload;
    userId: string;
    sid: string;
    ip?: string;
    userAgent?: string;
  }): Promise<never> {
    const { payload, userId, sid, ip, userAgent } = args;

    const nip = ip ? normalizeIp(ip) : null;
    const ua = userAgent?.trim() || null;

    this.logger.warn(
      'Refresh reuse detected or token already revoked',
      AuthService.name,
      {
        event: 'auth.refresh.reuse_detected',
        userId,
        jti: payload.jti,
        sid,
        ipMasked: nip ? maskIp(nip) : undefined,
        uaHash: ua ? hashId(ua) : undefined,
      },
    );

    const { revokedTokens, terminatedSessions } =
      await this.lifecycle.revokeAllAndTerminateAll({
        userId,
        reason: 'refresh_reuse_detected',
      });

    this.logger.warn(
      'Refresh reuse response applied (user-wide revoke all tokens + terminate all sessions)',
      AuthService.name,
      {
        event: 'auth.refresh.reuse_response_applied_user_wide',
        userId,
        reuseJti: payload.jti,
        reuseSid: sid,
        revokedTokens,
        terminatedSessions,
      },
    );

    throw new UnauthorizedException('Токен відкликано або недійсний');
  }

  private async getUserOrThrow(
    userId: string,
    payload: JwtPayload,
  ): Promise<{ id: string; email: string; role: Role }> {
    const user = await this.usersService.findById(userId);
    if (user) return user;

    this.logger.warn('Refresh failed: user not found', AuthService.name, {
      event: 'auth.refresh.fail',
      reason: 'user_not_found',
      userId,
      jti: payload.jti,
      sid: payload.sid,
    });

    throw new UnauthorizedException('Користувача не знайдено');
  }
}
