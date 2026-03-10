import { Injectable, UnauthorizedException } from '@nestjs/common';

import { RefreshTokenService } from 'src/sessions/refresh-token.service';
import { SessionLifecycleService } from 'src/sessions/session-lifecycle.service';
import type { Tokens } from '../types/jwt.types';
import type { AuthRequestContext } from './types/auth-request-context';

import { RefreshVerifier } from './refresh/refresh.verifier';
import {
  RefreshRotationService,
  RefreshClaimFailed,
} from './refresh/refresh.rotation.service';
import { RefreshIncidentResponseService } from './refresh/refresh.incident-response.service';

import { normalizeIp } from 'src/common/net/ip-normalize';
import { UsersService } from 'src/users/users.service';
import { AppLogger } from 'src/logger/logger.service';

@Injectable()
export class RefreshUseCase {
  constructor(
    private readonly verifier: RefreshVerifier,
    private readonly rotation: RefreshRotationService,
    private readonly incidents: RefreshIncidentResponseService,
    private readonly refreshTokenService: RefreshTokenService,
    private readonly usersService: UsersService,
    private readonly lifecycle: SessionLifecycleService,
    private readonly logger: AppLogger,
  ) {
    this.logger.setContext(RefreshUseCase.name);
  }

  async execute(
    refreshToken: string,
    ctx: AuthRequestContext,
  ): Promise<Tokens> {
    const payload = await this.verifier.verifyRefreshOrThrow(refreshToken);

    const userId = this.verifier.requireUserId(payload);

    const jti = this.verifier.requireJti(payload);

    const sid = this.verifier.requireSid(payload, userId);

    await this.verifier.assertSessionActiveOrThrow({
      sid,
      userId,
      payload,
      ip: ctx.ip,
      userAgent: ctx.userAgent,
    });

    await this.refreshTokenService.assertFingerprint({
      userId,
      jti,
      sid,
      ip: ctx.ip ? normalizeIp(ctx.ip) : null,
      userAgent: ctx.userAgent?.trim() || null,
    });

    const user = await this.verifier.getUserOrThrow(userId, payload);

    const snap = await this.usersService.getAuthSnapshotById(userId);
    const dbTokenVersion = snap?.tokenVersion ?? 0;
    const payloadTokenVersion = typeof payload.tv === 'number' ? payload.tv : 0;

    if (payloadTokenVersion !== dbTokenVersion) {
      this.logger.warn(
        'Refresh blocked: tokenVersion mismatch',
        RefreshUseCase.name,
        {
          event: 'auth.refresh.blocked',
          reason: 'token_version_mismatch',
          userId,
          sid,
          jti,
          payloadTv: payloadTokenVersion,
          dbTv: dbTokenVersion,
        },
      );

      await this.lifecycle.revokeJtiAndTerminateSession({
        userId,
        jti,
        sid,
        reason: 'security_policy',
      });

      throw new UnauthorizedException('Токен відкликано або недійсний');
    }

    try {
      return await this.rotation.rotateAtomic({
        user: { ...user, tokenVersion: dbTokenVersion },
        sid,
        oldJti: jti,
        refreshToken,
        ip: ctx.ip,
        userAgent: ctx.userAgent,
      });
    } catch (e: unknown) {
      if (e instanceof RefreshClaimFailed) {
        return this.incidents.handleReuseDetected({
          payload: { ...payload, jti },
          userId,
          sid,
          ip: ctx.ip,
          userAgent: ctx.userAgent,
          geo: ctx.geo,
        });
      }
      throw e;
    }
  }
}
