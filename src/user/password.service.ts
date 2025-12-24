import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { RedisService } from 'src/redis/redis.service';
import * as crypto from 'crypto';
import * as bcrypt from 'bcrypt';

import { UserDbService } from './user.db.service';
import { PasswordDbService } from './password.db.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { TokenService } from 'src/token/token.service';

@Injectable()
export class PasswordService {
  constructor(
    private redisService: RedisService,
    private usersDbService: UserDbService,
    private passwordDbService: PasswordDbService,
    private tokenService: TokenService,
    private prisma: PrismaService,
  ) {}

  private hashPasswordResetToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  async createPasswordResetToken(
    userId: string,
    ip: string,
    userAgent: string,
  ): Promise<{ token: string; hashedToken: string }> {
    const token = crypto.randomBytes(40).toString('hex');
    const ttl = 60 * 2;
    const hashedToken = this.hashPasswordResetToken(token);
    const key = `pwdreset:token:${hashedToken}`;

    await this.redisService.set(
      key,
      JSON.stringify({
        userId,
        ip,
        userAgent,
      }),
      ttl,
    );

    return { token: token, hashedToken: hashedToken };
  }

  async paswordReset(
    passwordResetToken: string,
    password: string,
    rePassword: string,
  ) {
    const inComingToken = this.hashPasswordResetToken(passwordResetToken);

    const data = await this.redisService.get(`pwdreset:token:${inComingToken}`);
    const parsed = JSON.parse(data);

    if (!data) throw new UnauthorizedException('Invalid or expired token');

    const user = await this.usersDbService.findOneById(parsed.userId);

    if (!user) {
      throw new UnauthorizedException('Invalid or expired token');
    }

    if (password !== rePassword) {
      throw new BadRequestException('Passwords do not match');
    }

    const passwordResetData =
      await this.passwordDbService.getPasswordResetByUserAndToken({
        userId: parsed.userId,
        token: inComingToken,
      });

    if (!passwordResetData) {
      throw new BadRequestException('Invalid or expired token');
    }
    if (passwordResetData.tokenUsed)
      throw new UnauthorizedException('Password reset token already used');

    if (passwordResetData.expiresAt < new Date())
      throw new UnauthorizedException('Password reset token expired');

    const hashedPassword = await bcrypt.hash(password, 10);

    await this.prisma.$transaction(async (tx) => {
      await tx.user.update({
        where: { id: parsed.userId },
        data: { password: hashedPassword },
      });
      await tx.passwordReset.update({
        where: { id: passwordResetData.id },
        data: { tokenUsed: true },
      });
    });

    await this.redisService.del(`pwdreset:token:${inComingToken}`);
    await this.tokenService.logoutAllSessions(parsed.userId);

    return true;
  }

  async changePassword(
    userId: string,
    oldPassword: string,
    password: string,
    rePassword: string,
  ) {
    const user = await this.usersDbService.findOneById(userId);

    if (!user) {
      throw new UnauthorizedException();
    }

    if (!oldPassword) {
      throw new BadRequestException('Missing parameter');
    }

    if (!oldPassword || !password || !rePassword) {
      throw new BadRequestException('Missing parameter');
    }

    if (password !== rePassword) {
      throw new BadRequestException('Passwords do not match');
    }

    const isMatch = await bcrypt.compare(oldPassword, user.password);

    if (!isMatch) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const hashedNewPassword = await bcrypt.hash(password, 10);

    await this.usersDbService.update(userId, { password: hashedNewPassword });

    await this.tokenService.logoutAllSessions(userId);

    return true;
  }
}
