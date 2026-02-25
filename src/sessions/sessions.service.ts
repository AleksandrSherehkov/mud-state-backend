import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { SessionRepositoryService } from './session-repository.service';
import { SessionTerminationService } from './session-termination.service';
import { RefreshBindingService } from './refresh-binding.service';
import { AccessAnomalyService } from './access-anomaly.service';

@Injectable()
export class SessionsService {
  constructor(
    private readonly repo: SessionRepositoryService,
    private readonly termination: SessionTerminationService,
    private readonly refreshBinding: RefreshBindingService,
    private readonly accessAnomaly: AccessAnomalyService,
  ) {}

  create(
    sessionId: string,
    userId: string,
    refreshTokenJti: string,
    ip?: string,
    userAgent?: string,
    geo?: { country?: string; asn?: number; asOrgHash?: string },
    tx?: Prisma.TransactionClient,
  ) {
    return this.repo.create(
      sessionId,
      userId,
      refreshTokenJti,
      ip,
      userAgent,
      geo,
      tx,
    );
  }

  getUserSessions(userId: string) {
    return this.repo.getUserSessions(userId);
  }

  getActiveUserSessions(userId: string, take = 50) {
    return this.repo.getActiveUserSessions(userId, take);
  }

  getAllUserSessions(userId: string) {
    return this.repo.getAllUserSessions(userId);
  }

  countActive(userId: string) {
    return this.repo.countActive(userId);
  }

  isSessionActive(sessionId: string, userId: string) {
    return this.repo.isSessionActive(sessionId, userId);
  }

  isSessionActiveById(sessionId: string) {
    return this.repo.isSessionActiveById(sessionId);
  }

  getActiveSessionContext(params: { sid: string; userId: string }) {
    return this.repo.getActiveSessionContext(params);
  }

  getActiveSessionBinding(params: { sid: string; userId: string }) {
    return this.refreshBinding.getActiveSessionBinding(params);
  }

  updateRefreshBinding(params: {
    sid: string;
    userId: string;
    newJti: string;
    ip?: string | null;
    userAgent?: string | null;
    tx?: Prisma.TransactionClient;
  }) {
    return this.refreshBinding.updateRefreshBinding(params);
  }

  enforceMaxActiveSessions(params: {
    userId: string;
    maxActive: number;
    meta?: Record<string, unknown>;
    tx: Prisma.TransactionClient;
  }) {
    return this.termination.enforceMaxActiveSessions(params);
  }

  terminateOtherSessions(userId: string, excludeSessionId: string) {
    return this.termination.terminateOtherSessions(userId, excludeSessionId);
  }

  terminateAll(userId: string) {
    return this.termination.terminateAll(userId);
  }

  terminateByRefreshToken(jti: string) {
    return this.termination.terminateByRefreshToken(jti);
  }

  terminateById(params: { sid: string; userId: string; reason?: string }) {
    return this.termination.terminateById(params);
  }

  assertAccessContext(params: {
    sid: string;
    userId: string;
    ip?: string | null;
    userAgent?: string | null;
    geo?: { country?: string; asn?: number; asOrgHash?: string };
  }) {
    return this.accessAnomaly.assertAccessContext(params);
  }
}
