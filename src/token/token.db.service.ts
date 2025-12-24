import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { Prisma, Token } from '@prisma/client';

@Injectable()
export class TokenDbService {
  constructor(private prisma: PrismaService) {}

  async findOneById(id: any): Promise<Token | null> {
    return this.prisma.token.findUnique({
      where: { id },
    });
  }

  create(data: Prisma.TokenCreateInput): Promise<Token> {
    return this.prisma.token.create({ data });
  }
  async findActiveSessionIdsByUser(userId: string): Promise<number[]> {
    const sessions = await this.prisma.token.findMany({
      where: {
        userId,
        revokedAt: null,
        expiresAt: { gt: new Date() },
      },
      select: { id: true },
    });
    return sessions.map((s) => s.id);
  }

  async revokeAllByUser(userId: string) {
    return this.prisma.token.updateMany({
      where: { userId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
  }

  async revokeById(sessionıd: any): Promise<Token> {
    return this.prisma.token.update({
      where: { id: sessionıd },
      data: {
        revokedAt: new Date(),
      },
    });
  }
}
