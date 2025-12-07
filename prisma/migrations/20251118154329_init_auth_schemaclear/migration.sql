/*
  Warnings:

  - Added the required column `last_used_at` to the `tokens` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "tokens" ADD COLUMN     "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN     "last_used_at" TIMESTAMP(3) NOT NULL,
ADD COLUMN     "revoked_at" TIMESTAMP(3);
