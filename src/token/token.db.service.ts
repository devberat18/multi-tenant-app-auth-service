import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { Prisma, Token } from '@prisma/client';
import { SessionStatus } from 'src/auth/dto';

export interface TokenSessionListDbArgs {
  userId: string;
  status?: SessionStatus;
  cursorId?: number;
  take?: number;
  from?: Date;
  to?: Date;
}

@Injectable()
export class TokenDbService {
  constructor(private prisma: PrismaService) {}

  async findOneById(id: number): Promise<Token | null> {
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

  async revokeById(sessionıd: number): Promise<Token> {
    return this.prisma.token.update({
      where: { id: sessionıd },
      data: {
        revokedAt: new Date(),
      },
    });
  }

  async listUserSessionsCursor(
    args: TokenSessionListDbArgs,
  ): Promise<{ data; nextCursorId: number | null; hasNextPage; take }> {
    const now = new Date();

    const take = Math.min(args.take ?? 20, 50);
    const status: SessionStatus = args.status ?? 'active';

    const where: any = { userId: args.userId };

    if (status === 'active') {
      where.revokedAt = null;
      where.expiresAt = { gt: now };
    } else if (status === 'revoked') {
      where.revokedAt = { not: null };
    } else if (status === 'expired') {
      where.expiresAt = { lte: now };
    }

    if (args.from || args.to) {
      where.createdAt = {};
      if (args.from) where.createdAt.gte = args.from;
      if (args.to) where.createdAt.lte = args.to;
    }

    const rows = await this.prisma.token.findMany({
      where,
      select: {
        id: true,
        ip: true,
        userDevice: true,
        createdAt: true,
        lastUsedAt: true,
        expiresAt: true,
        revokedAt: true,
      },
      orderBy: { id: 'desc' },
      take: take + 1,
      ...(args.cursorId
        ? {
            cursor: { id: args.cursorId },
            skip: 1,
          }
        : {}),
    });

    const hasNextPage = rows.length > take;
    const data = hasNextPage ? rows.slice(0, take) : rows;

    return {
      data,
      nextCursorId: hasNextPage ? data[data.length - 1].id : null,
      hasNextPage,
      take,
    };
  }
}
