import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { PasswordReset, Prisma } from '@prisma/client';

@Injectable()
export class PasswordDbService {
  constructor(private prisma: PrismaService) {}

  create(data: Prisma.PasswordResetCreateInput): Promise<PasswordReset> {
    return this.prisma.passwordReset.create({ data });
  }

  update(
    id: bigint,
    data: Prisma.PasswordResetUpdateInput,
  ): Promise<PasswordReset> {
    return this.prisma.passwordReset.update({ where: { id }, data });
  }

  async getPasswordResetByUserAndToken(params: {
    userId: string;
    token: string;
  }) {
    const now = new Date();

    return this.prisma.passwordReset.findFirst({
      where: {
        userId: params.userId,
        tokenUsed: false,
        token: params.token,
        expiresAt: {
          gte: now,
        },
      },
    });
  }
}
