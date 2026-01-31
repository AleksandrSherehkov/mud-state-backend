-- 1) drop FKs referencing User(id)
ALTER TABLE "Character"    DROP CONSTRAINT IF EXISTS "Character_userId_fkey";
ALTER TABLE "RefreshToken" DROP CONSTRAINT IF EXISTS "RefreshToken_userId_fkey";
ALTER TABLE "Session"      DROP CONSTRAINT IF EXISTS "Session_userId_fkey";
ALTER TABLE "UserSecurity" DROP CONSTRAINT IF EXISTS "UserSecurity_userId_fkey";

-- 2) alter PK column type safely (no drop pkey)
ALTER TABLE "User"
  ALTER COLUMN "id" TYPE uuid USING "id"::uuid;

-- 3) alter referencing columns
ALTER TABLE "Character"
  ALTER COLUMN "userId" TYPE uuid USING "userId"::uuid;

ALTER TABLE "RefreshToken"
  ALTER COLUMN "userId" TYPE uuid USING "userId"::uuid;

ALTER TABLE "Session"
  ALTER COLUMN "userId" TYPE uuid USING "userId"::uuid;

ALTER TABLE "UserSecurity"
  ALTER COLUMN "userId" TYPE uuid USING "userId"::uuid;

-- 4) (optional) if Session.id also changed type in your schema
ALTER TABLE "Session"
  ALTER COLUMN "id" TYPE uuid USING "id"::uuid;

-- 5) restore FKs
ALTER TABLE "Character"
  ADD CONSTRAINT "Character_userId_fkey"
  FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE;

ALTER TABLE "RefreshToken"
  ADD CONSTRAINT "RefreshToken_userId_fkey"
  FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE;

ALTER TABLE "Session"
  ADD CONSTRAINT "Session_userId_fkey"
  FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE;

ALTER TABLE "UserSecurity"
  ADD CONSTRAINT "UserSecurity_userId_fkey"
  FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE;
