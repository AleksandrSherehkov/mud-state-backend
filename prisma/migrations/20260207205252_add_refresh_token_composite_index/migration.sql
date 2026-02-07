-- CreateIndex
CREATE INDEX "RefreshToken_userId_revoked_expiresAt_idx" ON "RefreshToken"("userId", "revoked", "expiresAt");
