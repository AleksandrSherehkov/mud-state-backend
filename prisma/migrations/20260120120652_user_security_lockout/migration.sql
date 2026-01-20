-- CreateTable
CREATE TABLE "UserSecurity" (
    "userId" TEXT NOT NULL,
    "failedLoginCount" INTEGER NOT NULL DEFAULT 0,
    "lastFailedAt" TIMESTAMP(3),
    "lockedUntil" TIMESTAMP(3),
    "lastFailedIp" TEXT,
    "lastFailedUaHash" TEXT,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "UserSecurity_pkey" PRIMARY KEY ("userId")
);

-- CreateIndex
CREATE INDEX "UserSecurity_lockedUntil_idx" ON "UserSecurity"("lockedUntil");

-- CreateIndex
CREATE INDEX "UserSecurity_lastFailedAt_idx" ON "UserSecurity"("lastFailedAt");

-- AddForeignKey
ALTER TABLE "UserSecurity" ADD CONSTRAINT "UserSecurity_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
