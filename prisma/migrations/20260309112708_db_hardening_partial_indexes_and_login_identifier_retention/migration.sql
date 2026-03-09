-- CreateIndex
CREATE INDEX "LoginIdentifierSecurity_updatedAt_idx" ON "LoginIdentifierSecurity"("updatedAt");

CREATE INDEX IF NOT EXISTS "session_active_user_started_idx"
  ON "Session" ("userId", "startedAt" DESC)
  WHERE "isActive" = true AND "endedAt" IS NULL;

CREATE INDEX IF NOT EXISTS "session_active_id_user_idx"
  ON "Session" ("id", "userId")
  WHERE "isActive" = true AND "endedAt" IS NULL;

CREATE INDEX IF NOT EXISTS "session_active_refresh_token_jti_idx"
  ON "Session" ("refreshTokenJti")
  WHERE "isActive" = true AND "endedAt" IS NULL;

CREATE INDEX IF NOT EXISTS "refresh_token_not_revoked_user_expires_idx"
  ON "RefreshToken" ("userId", "expiresAt" DESC)
  WHERE "revoked" = false;

CREATE INDEX IF NOT EXISTS "refresh_token_not_revoked_jti_user_idx"
  ON "RefreshToken" ("jti", "userId")
  WHERE "revoked" = false;