import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import * as crypto from 'crypto';
import { RedisService } from 'src/redis/redis.service';
import { TokenDbService } from './token.db.service';
import { SessionStatus } from 'src/auth/dto';

export interface ListSessionsQuery {
  status?: SessionStatus;
  cursorId?: number | string;
  take?: number | string;
  from?: string;
  to?: string;
}

type RevokeSessionResult =
  | { success: true; status: 'revoked' }
  | { success: true; status: 'already_revoked' }
  | { success: true; status: 'already_expired' };

type logoutSessionsResult = { success: true };

type RefreshSessionResult = {
  userId: string;
  newRefreshToken: string;
  newSessionId: number;
};
type IssueSessionResult = { refreshToken: string; sessionId: number };

type ParseRefreshTokenResult = {
  sessionId: number;
  raw: string;
};
@Injectable()
export class TokenService {
  constructor(
    private redisService: RedisService,
    private tokenDbService: TokenDbService,
  ) {}

  private parseRefreshToken(refreshToken: string): ParseRefreshTokenResult {
    const [sid, raw] = refreshToken.split('.');
    const sessionId = Number(sid);
    if (!sid || !raw || !Number.isInteger(sessionId) || sessionId <= 0) {
      throw new UnauthorizedException('Invalid refresh token');
    }
    return { sessionId, raw };
  }

  private hashRefreshToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  async issueSession(
    userId: string,
    ip: string,
    userAgent: string,
  ): Promise<IssueSessionResult> {
    const token = crypto.randomBytes(40).toString('hex');
    const ttl = 7 * 24 * 60 * 60;
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 7);
    const hashedToken = this.hashRefreshToken(token);

    const session = await this.tokenDbService.create({
      refreshToken: hashedToken,
      ip,
      userDevice: userAgent,
      expiresAt,
      lastUsedAt: new Date(),
      user: { connect: { id: userId } },
    });

    const key = `refresh_token:${session.id}`;

    await this.redisService.set(
      key,
      JSON.stringify({
        ip,
        userAgent,
      }),
      ttl,
    );

    return { refreshToken: `${session.id}.${token}`, sessionId: session.id };
  }

  async refreshSession(
    refreshToken: string,
    ip: string,
    userAgent: string,
  ): Promise<RefreshSessionResult> {
    const { sessionId, raw } = this.parseRefreshToken(refreshToken);
    const incomingHash = this.hashRefreshToken(raw);
    const session = await this.tokenDbService.findOneById(sessionId);

    if (!session) throw new UnauthorizedException('Session not found');
    if (session.revokedAt) throw new UnauthorizedException('Session revoked');
    if (session.expiresAt < new Date())
      throw new UnauthorizedException('Session expired');

    if (incomingHash !== session.refreshToken) {
      // await this.tokenDbService.revokeAllByUser(session.userId);
      await this.logoutAllSessions(session.userId);
      throw new ForbiddenException('Refresh token reuse detected');
    }

    await this.tokenDbService.revokeById(sessionId);
    await this.redisService.set(`session:revoked:${sessionId}`, '1', 900); // access token TTL

    const rawNew = crypto.randomBytes(32).toString('hex');
    const newHash = this.hashRefreshToken(rawNew);
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    const newSession = await this.tokenDbService.create({
      refreshToken: newHash,
      ip: ip,
      userDevice: userAgent,
      expiresAt,
      lastUsedAt: new Date(),
      user: { connect: { id: session.userId } },
    });

    await this.redisService.set(
      `refresh_token:${newSession.id}`,
      JSON.stringify({ ip: ip, userAgent: userAgent }),
      7 * 24 * 60 * 60,
    );

    await this.redisService.del(`refresh_token:${sessionId}`);

    return {
      userId: session.userId,
      newRefreshToken: `${newSession.id}.${rawNew}`,
      newSessionId: newSession.id,
    };
  }

  async logutCurrentSession(
    refreshToken: string,
  ): Promise<logoutSessionsResult> {
    const { sessionId, raw } = this.parseRefreshToken(refreshToken);
    const session = await this.tokenDbService.findOneById(sessionId);

    if (!session || session.revokedAt) {
      throw new UnauthorizedException('Session not found or already revoked');
    }
    if (session.expiresAt < new Date()) {
      throw new UnauthorizedException('Session expired');
    }
    const incomingHash = this.hashRefreshToken(raw);
    if (incomingHash !== session.refreshToken) {
      throw new UnauthorizedException('Invalid refresh token');
    }
    await this.tokenDbService.revokeById(sessionId);
    await this.redisService.set(`session:revoked:${sessionId}`, '1', 900);
    await this.redisService.del(`refresh_token:${sessionId}`);

    return { success: true };
  }

  async logoutAllSessions(userId: string): Promise<logoutSessionsResult> {
    const activeSessionIds =
      await this.tokenDbService.findActiveSessionIdsByUser(userId);

    await this.tokenDbService.revokeAllByUser(userId);
    await Promise.allSettled(
      activeSessionIds.map((id) =>
        Promise.all([
          this.redisService.set(`session:revoked:${id}`, '1', 900),
          this.redisService.del(`refresh_token:${id}`),
        ]),
      ),
    );
    return { success: true };
  }

  async listMySessions(userId: string, q: ListSessionsQuery) {
    const status = (q.status ?? 'active') as SessionStatus;

    const take = q.take === undefined ? 20 : Number(q.take);
    if (Number.isNaN(take) || take < 1) {
      throw new BadRequestException('take must be a positive number');
    }

    const cursorId = q.cursorId === undefined ? undefined : Number(q.cursorId);
    if (q.cursorId !== undefined && (Number.isNaN(cursorId) || cursorId < 1)) {
      throw new BadRequestException('cursorId must be a positive number');
    }

    const from = q.from ? new Date(q.from) : undefined;
    const to = q.to ? new Date(q.to) : undefined;

    if (from && Number.isNaN(from.getTime())) {
      throw new BadRequestException('from must be a valid ISO date');
    }
    if (to && Number.isNaN(to.getTime())) {
      throw new BadRequestException('to must be a valid ISO date');
    }
    if (from && to && from > to) {
      throw new BadRequestException('from cannot be after to');
    }

    const result = await this.tokenDbService.listUserSessionsCursor({
      userId,
      status,
      take,
      cursorId,
      from,
      to,
    });

    return {
      items: result.data,
      pageInfo: {
        take: result.take,
        hasNextPage: result.hasNextPage,
        nextCursorId: result.nextCursorId,
      },
      filters: {
        status,
        from: q.from ?? null,
        to: q.to ?? null,
      },
    };
  }

  async revokeSession(
    userId: string,
    sessionId: number,
  ): Promise<RevokeSessionResult> {
    const now = new Date();
    const session = await this.tokenDbService.findOneById(sessionId);

    if (!session) {
      throw new NotFoundException('Session not found');
    }

    if (session.userId !== userId) {
      throw new ForbiddenException('Cannot revoke session');
    }

    if (session.revokedAt) {
      return { success: true, status: 'already_revoked' };
    }

    if (session.expiresAt <= now) {
      return { success: true, status: 'already_expired' };
    }

    await this.tokenDbService.revokeById(sessionId);
    await this.redisService.set(`session:revoked:${sessionId}`, '1', 900);
    await this.redisService.del(`refresh_token:${sessionId}`);

    return { success: true, status: 'revoked' };
  }
}
