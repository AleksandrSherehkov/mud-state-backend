import type { Prisma } from '@prisma/client';

export interface AuthSessionsPort {
  create(
    sessionId: string,
    userId: string,
    refreshTokenJti: string,
    ip?: string,
    userAgent?: string,
    tx?: Prisma.TransactionClient,
  ): Promise<unknown>;

  isSessionActive(sessionId: string, userId: string): Promise<boolean>;
  terminateAll(userId: string): Promise<{ count: number }>;
  terminateByRefreshToken(jti: string): Promise<{ count: number }>;
  terminateOtherSessions(
    userId: string,
    excludeSessionId: string,
  ): Promise<{ count: number }>;
}
