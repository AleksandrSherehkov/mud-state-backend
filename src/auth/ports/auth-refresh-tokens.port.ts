import type { Prisma } from '@prisma/client';

export interface AuthRefreshTokensPort {
  create(
    userId: string,
    jti: string,
    tokenHash: string,
    ip?: string,
    userAgent?: string,
    tx?: Prisma.TransactionClient,
  ): Promise<unknown>;

  revokeAll(userId: string): Promise<{ count: number }>;

  revokeIfActiveByHash(
    jti: string,
    userId: string,
    tokenHash: string,
  ): Promise<{ count: number }>;

  assertFingerprint(params: {
    userId: string;
    jti: string;
    sid: string;
    ip?: string | null;
    userAgent?: string | null;
  }): Promise<void>;
}
