/*
  Warnings:

  - You are about to alter the column `otp_code` on the `email_verification` table. The data in that column could be lost. The data in that column will be cast from `BigInt` to `VarChar(16)`.
  - You are about to alter the column `otp_code` on the `phone_verification` table. The data in that column could be lost. The data in that column will be cast from `BigInt` to `VarChar(16)`.

*/
-- CreateEnum
CREATE TYPE "UserStatus" AS ENUM ('ACTIVE', 'DEACTIVATED', 'BANNED', 'PENDING_VERIFICATION');

-- AlterTable
ALTER TABLE "email_verification" ALTER COLUMN "otp_code" SET DATA TYPE VARCHAR(16);

-- AlterTable
ALTER TABLE "phone_verification" ALTER COLUMN "otp_code" SET DATA TYPE VARCHAR(16);

-- AlterTable
ALTER TABLE "users" ADD COLUMN     "deactivatedAt" TIMESTAMP(3),
ADD COLUMN     "emailVerified" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "phoneVerified" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "status" "UserStatus" NOT NULL DEFAULT 'PENDING_VERIFICATION';
