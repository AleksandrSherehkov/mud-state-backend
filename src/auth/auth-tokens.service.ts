import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { randomUUID } from 'node:crypto';
import { Role } from '@prisma/client';

import { TokenService } from './token.service';
import { AuthTransactionService } from './auth-transaction.service';

import { RefreshTokenService } from 'src/sessions/refresh-token.service';
import { SessionsService } from 'src/sessions/sessions.service';

import { normalizeIp } from 'src/common/net/ip-normalize';
import { AppLogger } from 'src/logger/logger.service';
import { hashId, maskIp } from 'src/common/logging/log-sanitize';

import type { Tokens, JwtPayload } from './types/jwt.types';

@Injectable()
export class AuthTokensService {
  constructor(
    private readonly tokenService: TokenService,
    private readonly refreshTokenService: RefreshTokenService,
    private readonly sessionsService: SessionsService,
    private readonly tx: AuthTransactionService,
    private readonly logger: AppLogger,
    private readonly config: ConfigService,
  ) {
    this.logger.setContext(AuthTokensService.name);
  }

  private getMaxActiveSessions(): number {
    const raw = this.config.get<string>('AUTH_MAX_ACTIVE_SESSIONS') ?? '1';
    const n = Number.parseInt(raw, 10);
    if (!Number.isFinite(n)) return 10;
    return Math.min(Math.max(n, 1), 50);
  }

  async issueForUser(params: {
    userId: string;
    email: string;
    role: Role;
    ip?: string;
    userAgent?: string;
    geo?: { country?: string; asn?: number; asOrgHash?: string };
  }): Promise<Tokens> {
    const refreshJti = randomUUID();
    const sessionId = randomUUID();

    const nip: string | null = params.ip ? normalizeIp(params.ip) : null;
    const ua: string | null = params.userAgent ? params.userAgent.trim() : null;

    const payload: JwtPayload = {
      sub: params.userId,
      email: params.email,
      jti: refreshJti,
      role: params.role,
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
          userId: params.userId,
          maxActive,
          tx,
          meta: {
            event: 'auth.tokens.cap',
            sidNew: sessionId,
            jtiNew: refreshJti,
          },
        });

        await this.refreshTokenService.create(
          params.userId,
          refreshJti,
          tokenHash,
          tokenSalt,
          nip ?? undefined,
          ua ?? undefined,
          tx,
        );

        await this.sessionsService.create(
          sessionId,
          params.userId,
          refreshJti,
          nip ?? undefined,
          ua ?? undefined,
          params.geo,
          tx,
        );
      });
    } catch (err: unknown) {
      const errorName = err instanceof Error ? err.name : 'UnknownError';
      const errorMessage = err instanceof Error ? err.message : String(err);

      this.logger.error(
        'Tokens issue transaction failed',
        undefined,
        AuthTokensService.name,
        {
          event: 'auth.tokens.issue_failed',
          userId: params.userId,
          role: params.role,
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

    this.logger.log('Tokens issued', AuthTokensService.name, {
      event: 'auth.tokens.issued',
      userId: params.userId,
      role: params.role,
      jti: refreshJti,
      sid: sessionId,
      ipMasked: nip ? maskIp(nip) : undefined,
      uaHash: ua ? hashId(ua) : undefined,
    });

    return { accessToken, refreshToken, jti: refreshJti };
  }
}
