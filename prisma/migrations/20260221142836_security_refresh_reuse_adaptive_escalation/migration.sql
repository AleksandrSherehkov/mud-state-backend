-- AlterTable
ALTER TABLE "UserSecurity" ADD COLUMN     "lastRefreshReuseAsOrgHash" VARCHAR(64),
ADD COLUMN     "lastRefreshReuseAsn" INTEGER,
ADD COLUMN     "lastRefreshReuseAt" TIMESTAMP(3),
ADD COLUMN     "lastRefreshReuseCountry" CHAR(2),
ADD COLUMN     "refreshReuseCount" INTEGER NOT NULL DEFAULT 0;

-- CreateIndex
CREATE INDEX "UserSecurity_lastRefreshReuseAt_idx" ON "UserSecurity"("lastRefreshReuseAt");
