import {
  BadRequestException,
  HttpException,
  Injectable,
  InternalServerErrorException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class AuthDbService {
  constructor(private prisma: PrismaService) {}

  async findOne(params: {
    email?: string;
    username?: string;
    phone_number?: string;
  }) {
    try {
      if (!params.email && !params.username && !params.phone_number) {
        throw new BadRequestException(
          'Either email or username must be provided',
        );
      }

      return this.prisma.user.findFirst({
        where: {
          OR: [
            params.email ? { email: params.email } : undefined,
            params.phone_number
              ? { phone_number: params.phone_number }
              : undefined,
            params.username ? { username: params.username } : undefined,
          ].filter(Boolean),
        },
      });
    } catch (error) {
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException('Failed to fetch user');
    }
  }

  async findById(params: { userId: string }) {
    try {
      return this.prisma.user.findFirst({
        where: {
          id: params.userId,
        },
      });
    } catch (error) {
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException('Failed to fetch user');
    }
  }

  async createUser(params: {
    username: string;
    email: string;
    phone_number: string;
    password: string;
  }) {
    try {
      return await this.prisma.user.create({
        data: {
          email: params.email,
          username: params.username,
          phone_number: params.phone_number,
          password: params.password,
          role: 'user',
        },
      });
    } catch (error) {
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException('Failed to create user');
    }
  }

  async updateLastLogin(params: { userId: string }) {
    try {
      return this.prisma.user.update({
        where: { id: params.userId },
        data: { last_login: new Date() },
      });
    } catch (error) {
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException('ERROR');
    }
  }

  async updatePassword(params: { userId: string; password: string }) {
    try {
      return this.prisma.user.update({
        where: { id: params.userId },
        data: { password: params.password },
      });
    } catch (error) {
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException('ERROR');
    }
  }

  async updateResetPasswordTokenUsed(params: { tokenId: any }) {
    try {
      return this.prisma.passwordReset.update({
        where: { id: params.tokenId },
        data: { tokenUsed: true },
      });
    } catch (error) {
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException('ERROR');
    }
  }

  async createPasswordReset(params: {
    userId: string;
    ip: string;
    userDevice: string;
    token: string;
  }) {
    try {
      return await this.prisma.passwordReset.create({
        data: {
          userId: params.userId,
          ip: params.ip,
          userDevice: params.userDevice,
          token: params.token,
          createdAt: new Date(),
          expiresAt: new Date(Date.now() + 2 * 60 * 1000),
        },
      });
    } catch (error) {
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException('Failed to create');
    }
  }

  async getPasswordResetByUserAndToken(params: {
    userId: string;
    token: string;
  }) {
    const now = new Date();
    const twoMinutesFromNow = new Date(now.getTime() + 2 * 60 * 1000);

    return this.prisma.passwordReset.findFirst({
      where: {
        userId: params.userId,
        tokenUsed: false,
        token: params.token,
        expiresAt: {
          gte: now,
          lte: twoMinutesFromNow,
        },
      },
    });
  }
}
