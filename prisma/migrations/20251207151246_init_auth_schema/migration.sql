/*
  Warnings:

  - You are about to drop the column `tokenId` on the `password_reset` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "password_reset" DROP COLUMN "tokenId";
