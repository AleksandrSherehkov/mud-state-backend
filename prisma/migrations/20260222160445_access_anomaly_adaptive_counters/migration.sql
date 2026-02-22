-- AlterTable
ALTER TABLE "UserSecurity" ADD COLUMN     "accessAnomalyCount" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "lastAccessAnomalyAt" TIMESTAMP(3);

-- CreateIndex
CREATE INDEX "UserSecurity_lastAccessAnomalyAt_idx" ON "UserSecurity"("lastAccessAnomalyAt");
