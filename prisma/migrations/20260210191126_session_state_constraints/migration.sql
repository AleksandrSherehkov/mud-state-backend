-- 1) Backfill дрейфа, чтобы constraints не упали на существующих данных

UPDATE "Session"
SET "endedAt" = "startedAt"
WHERE "endedAt" IS NOT NULL AND "endedAt" < "startedAt";

UPDATE "Session"
SET "endedAt" = COALESCE("endedAt", "startedAt")
WHERE "isActive" = FALSE AND "endedAt" IS NULL;

UPDATE "Session"
SET "isActive" = FALSE
WHERE "isActive" = TRUE AND "endedAt" IS NOT NULL;


-- 2) CHECK: isActive ↔ endedAt
ALTER TABLE "Session"
  ADD CONSTRAINT "session_state_consistency_chk"
  CHECK (
    ("isActive" = TRUE  AND "endedAt" IS NULL) OR
    ("isActive" = FALSE AND "endedAt" IS NOT NULL)
  );

-- 3) CHECK: endedAt >= startedAt
ALTER TABLE "Session"
  ADD CONSTRAINT "session_time_consistency_chk"
  CHECK (
    "endedAt" IS NULL OR "endedAt" >= "startedAt"
  );
