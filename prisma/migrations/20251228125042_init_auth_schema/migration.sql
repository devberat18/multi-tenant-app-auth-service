-- AlterTable
ALTER TABLE "tokens" ALTER COLUMN "last_used_at" DROP NOT NULL;

-- AlterTable
ALTER TABLE "users" ALTER COLUMN "last_login" DROP NOT NULL,
ALTER COLUMN "last_login" DROP DEFAULT;
