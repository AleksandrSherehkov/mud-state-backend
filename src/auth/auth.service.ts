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
import { SessionService } from 'src/sessions/session.service';

@Injectable()
export class AuthService {
  private readonly dummyPasswordHash: string;
  constructor(
    private readonly usersService: UsersService,
    private readonly tokenService: TokenService,
    private readonly refreshTokenService: RefreshTokenService,
    private readonly sessionService: SessionService,
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

    await this.claimRefreshOrHandleReuse({
      refreshToken,
      payload,
      userId,
      sid,
      ip,
      userAgent,
    });

    const user = await this.getUserOrThrow(userId, payload);

    return this.rotateAndIssueTokens({
      user,
      sid,
      oldJti: payload.jti,
      ip,
      userAgent,
    });
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

  async getMe(userId: string) {
    const user = await this.usersService.findById(userId);
    if (!user) throw new NotFoundException('Користувача не знайдено');
    return user;
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

    const tokenHash = this.tokenService.hashRefreshToken(refreshToken);

    try {
      await this.tx.run(async (tx) => {
        await this.refreshTokenService.create(
          userId,
          refreshJti,
          tokenHash,
          nip ?? undefined,
          ua ?? undefined,
          tx,
        );

        await this.sessionService.create(
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

    const sessionActive = await this.sessionService.isSessionActive(
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

  private async claimRefreshOrHandleReuse(args: {
    refreshToken: string;
    payload: JwtPayload;
    userId: string;
    sid: string;
    ip?: string;
    userAgent?: string;
  }): Promise<void> {
    const { refreshToken, payload, userId, sid, ip, userAgent } = args;

    const tokenHash = this.tokenService.hashRefreshToken(refreshToken);

    const claim = await this.refreshTokenService.revokeIfActiveByHash(
      payload.jti,
      userId,
      tokenHash,
    );

    if (claim.count !== 0) return;

    await this.handleRefreshReuseDetected({
      payload,
      userId,
      sid,
      ip,
      userAgent,
    });
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
    // Risk-based: не даємо "kill switch" по старому refresh.
    // Якщо jti з токена НЕ дорівнює поточному binding у Session — це stale token → 401 без terminate.
    const binding = await this.sessionService.getActiveSessionBinding({
      sid,
      userId,
    });

    const boundJti = binding?.refreshTokenJti ?? null;

    // Якщо сесія вже неактивна — просто 401 (без зайвих побічних ефектів)
    if (!binding) {
      this.logger.warn('Refresh reuse: session not active', AuthService.name, {
        event: 'auth.refresh.reuse_detected',
        userId,
        jti: payload.jti,
        sid,
        reason: 'session_inactive',
      });

      throw new UnauthorizedException('Токен відкликано або недійсний');
    }

    // Сценарій DoS: old refresh (старий jti) → НЕ terminate sid
    if (boundJti && boundJti !== payload.jti) {
      await this.refreshTokenService.revokeManyByJtis([payload.jti], {
        userId,
        jti: payload.jti,
        sid,
        boundJti,
        reason: 'reuse_detected_stale_jti_no_kill',
      });

      this.logger.warn(
        'Refresh reuse (stale jti) blocked without terminate',
        AuthService.name,
        {
          event: 'auth.refresh.reuse_detected_stale_jti',
          userId,
          sid,
          tokenJti: payload.jti,
          boundJti,
        },
      );

      throw new UnauthorizedException('Токен відкликано або недійсний');
    }

    // Якщо boundJti == payload.jti, але claim не пройшов — це вже підозріло в межах поточного binding.

    const [revoked, terminated] = await Promise.all([
      this.refreshTokenService.revokeManyByJtis([payload.jti], {
        userId,
        jti: payload.jti,
        sid,
        boundJti,
        reason: 'reuse_detected_bound_jti_terminate',
      }),
      this.sessionService.terminateById({
        sid,
        userId,
        reason: 'reuse_detected_bound_jti_terminate',
      }),
    ]);

    this.logger.warn(
      'Refresh reuse response applied (bound jti -> terminate)',
      AuthService.name,
      {
        event: 'auth.refresh.reuse_response_applied_bound_jti',
        userId,
        jti: payload.jti,
        sid,
        revokedTokens: revoked.count,
        terminatedSessions: terminated.count,
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

  private async rotateAndIssueTokens(args: {
    user: { id: string; email: string; role: Role };
    sid: string;
    oldJti: string;
    ip?: string;
    userAgent?: string;
  }): Promise<Tokens> {
    const { user, sid, oldJti, ip, userAgent } = args;

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

    const newTokenHash = this.tokenService.hashRefreshToken(newRefreshToken);

    await this.tx.run(async (tx) => {
      await this.refreshTokenService.create(
        user.id,
        newJti,
        newTokenHash,
        nip ?? undefined,
        ua ?? undefined,
        tx,
      );

      await this.sessionService.updateRefreshBinding({
        sid,
        userId: user.id,
        newJti,
        ip: nip,
        userAgent: ua,
        tx,
      });
    });

    this.logger.log(
      'Refresh success (session stable, jti rotated)',
      AuthService.name,
      {
        event: 'auth.refresh.success',
        userId: user.id,
        role: user.role,
        oldJti,
        newJti,
        sid,
      },
    );

    return { accessToken, refreshToken: newRefreshToken, jti: newJti };
  }
}
