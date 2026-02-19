/*
  Warnings:

  - A unique constraint covering the columns `[jti,userId]` on the table `RefreshToken` will be added. If there are existing duplicate values, this will fail.

*/
-- DropForeignKey
ALTER TABLE "Session" DROP CONSTRAINT "Session_refreshTokenJti_fkey";

-- CreateIndex
CREATE UNIQUE INDEX "rt_jti_userid_uq" ON "RefreshToken"("jti", "userId");

-- AddForeignKey
ALTER TABLE "Session" ADD CONSTRAINT "Session_refreshTokenJti_userId_fkey"
FOREIGN KEY ("refreshTokenJti", "userId")
REFERENCES "RefreshToken"("jti", "userId")
ON DELETE RESTRICT ON UPDATE CASCADE;

-- =========================
-- Security DB invariants
-- =========================

-- Make this migration idempotent for Prisma shadow DB
ALTER TABLE "Session" DROP CONSTRAINT IF EXISTS "session_state_consistency_chk";
ALTER TABLE "Session" DROP CONSTRAINT IF EXISTS "session_time_consistency_chk";
DROP INDEX IF EXISTS "session_active_refresh_token_jti_uq";

ALTER TABLE "Session"
  ADD CONSTRAINT "session_state_consistency_chk"
  CHECK (
    ("isActive" = TRUE  AND "endedAt" IS NULL) OR
    ("isActive" = FALSE AND "endedAt" IS NOT NULL)
  );

ALTER TABLE "Session"
  ADD CONSTRAINT "session_time_consistency_chk"
  CHECK (
    "endedAt" IS NULL OR "endedAt" >= "startedAt"
  );

CREATE UNIQUE INDEX "session_active_refresh_token_jti_uq"
ON "Session" ("refreshTokenJti")
WHERE
  "refreshTokenJti" IS NOT NULL
  AND "isActive" = TRUE
  AND "endedAt" IS NULL;
