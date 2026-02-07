/*
  Warnings:

  - Added the required column `tokenSalt` to the `RefreshToken` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "RefreshToken" ADD COLUMN     "tokenSalt" VARCHAR(32) NOT NULL;
