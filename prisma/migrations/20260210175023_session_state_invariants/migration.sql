-- CreateIndex
CREATE INDEX "Session_userId_isActive_endedAt_startedAt_idx"
ON "Session"("userId", "isActive", "endedAt", "startedAt");

-- CreateIndex
CREATE INDEX "Session_userId_startedAt_idx"
ON "Session"("userId", "startedAt");

-- 0) Normalize existing data BEFORE adding constraint
-- inactive session must have endedAt
UPDATE "Session"
SET "endedAt" = NOW()
WHERE "isActive" = FALSE
  AND "endedAt" IS NULL;

-- active session must NOT have endedAt
UPDATE "Session"
SET "isActive" = FALSE
WHERE "isActive" = TRUE
  AND "endedAt" IS NOT NULL;

-- 1) Add invariant constraint
ALTER TABLE "Session"
  ADD CONSTRAINT "Session_state_invariant"
  CHECK (
    ("isActive" = TRUE  AND "endedAt" IS NULL)
    OR
    ("isActive" = FALSE AND "endedAt" IS NOT NULL)
  );
