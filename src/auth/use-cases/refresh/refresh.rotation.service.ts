import { Injectable, UnauthorizedException } from '@nestjs/common';
import { Role } from '@prisma/client';
import { randomUUID } from 'node:crypto';

import { TokenService } from '../../token.service';
import { AuthTransactionService } from '../../auth-transaction.service';

import { RefreshTokenService } from 'src/sessions/refresh-token.service';
import { SessionsService } from 'src/sessions/sessions.service';

import { AppLogger } from 'src/logger/logger.service';
import { normalizeIp } from 'src/common/net/ip-normalize';

import type { Tokens, JwtPayload } from '../../types/jwt.types';

export class RefreshClaimFailed extends Error {
  constructor() {
    super('refresh_claim_failed');
    this.name = 'RefreshClaimFailed';
  }
}

@Injectable()
export class RefreshRotationService {
  constructor(
    private readonly tokenService: TokenService,
    private readonly tx: AuthTransactionService,
    private readonly refreshTokenService: RefreshTokenService,
    private readonly sessionsService: SessionsService,
    private readonly logger: AppLogger,
  ) {
    this.logger.setContext(RefreshRotationService.name);
  }

  async rotateAtomic(params: {
    user: { id: string; email: string; role: Role };
    sid: string;
    oldJti: string;
    refreshToken: string;
    ip?: string;
    userAgent?: string;
  }): Promise<Tokens> {
    const nip: string | null = params.ip ? normalizeIp(params.ip) : null;
    const ua: string | null = params.userAgent?.trim() || null;

    const newJti = randomUUID();

    const newPayload: JwtPayload = {
      sub: params.user.id,
      email: params.user.email,
      role: params.user.role,
      sid: params.sid,
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
        {
          jti: params.oldJti,
          userId: params.user.id,
          refreshToken: params.refreshToken,
        },
        tx,
      );

      if (claim.count === 0) {
        throw new RefreshClaimFailed();
      }

      await this.refreshTokenService.create(
        params.user.id,
        newJti,
        newTokenHash,
        newSalt,
        nip ?? undefined,
        ua ?? undefined,
        tx,
      );

      const updatedCount = await this.sessionsService.updateRefreshBinding({
        sid: params.sid,
        userId: params.user.id,
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
      RefreshRotationService.name,
      {
        event: 'auth.refresh.success_atomic',
        userId: params.user.id,
        role: params.user.role,
        oldJti: params.oldJti,
        newJti,
        sid: params.sid,
      },
    );

    return { accessToken, refreshToken: newRefreshToken, jti: newJti };
  }
}
