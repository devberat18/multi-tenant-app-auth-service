/*
  Warnings:

  - A unique constraint covering the columns `[token]` on the table `password_reset` will be added. If there are existing duplicate values, this will fail.

*/
-- AlterTable
ALTER TABLE "password_reset" ADD COLUMN     "ip" TEXT,
ADD COLUMN     "user_device" TEXT,
ALTER COLUMN "token" SET DATA TYPE TEXT;

-- CreateIndex
CREATE UNIQUE INDEX "password_reset_token_key" ON "password_reset"("token");
