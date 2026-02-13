CREATE TABLE "LoginAbuseCounter" (
    "key" VARCHAR(96) NOT NULL,
    "kind" VARCHAR(16) NOT NULL,
    "failedCount" INTEGER NOT NULL DEFAULT 0,
    "windowStartedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lockedUntil" TIMESTAMP(3),
    "lastFailedAt" TIMESTAMP(3),
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "LoginAbuseCounter_pkey" PRIMARY KEY ("key")
);

CREATE INDEX "LoginAbuseCounter_kind_lockedUntil_idx" ON "LoginAbuseCounter"("kind", "lockedUntil");
CREATE INDEX "LoginAbuseCounter_kind_lastFailedAt_idx" ON "LoginAbuseCounter"("kind", "lastFailedAt");
