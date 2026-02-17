/*
  Warnings:

  - You are about to alter the column `lastFailedUaHash` on the `UserSecurity` table. The data in that column could be lost. The data in that column will be cast from `Text` to `VarChar(64)`.

*/
-- AlterTable
ALTER TABLE "UserSecurity" ALTER COLUMN "lastFailedUaHash" SET DATA TYPE VARCHAR(64);

-- CreateTable
CREATE TABLE "LoginIdentifierSecurity" (
    "emailHash" VARCHAR(64) NOT NULL,
    "failedLoginCount" INTEGER NOT NULL DEFAULT 0,
    "lastFailedAt" TIMESTAMP(3),
    "lockedUntil" TIMESTAMP(3),
    "lastFailedIp" VARCHAR(64),
    "lastFailedUaHash" VARCHAR(64),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "LoginIdentifierSecurity_pkey" PRIMARY KEY ("emailHash")
);

-- CreateIndex
CREATE INDEX "LoginIdentifierSecurity_lockedUntil_idx" ON "LoginIdentifierSecurity"("lockedUntil");

-- CreateIndex
CREATE INDEX "LoginIdentifierSecurity_lastFailedAt_idx" ON "LoginIdentifierSecurity"("lastFailedAt");
