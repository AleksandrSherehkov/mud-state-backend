-- DropIndex
DROP INDEX "Session_refreshTokenJti_isActive_idx";

-- DropIndex
DROP INDEX "Session_refreshTokenJti_isActive_key";

-- CreateIndex
CREATE INDEX "Session_refreshTokenJti_idx" ON "Session"("refreshTokenJti");

-- Partial unique index: only one ACTIVE session per refreshTokenJti
CREATE UNIQUE INDEX "Session_refreshTokenJti_active_unique"
ON "Session" ("refreshTokenJti")
WHERE "isActive" = true AND "refreshTokenJti" IS NOT NULL;

