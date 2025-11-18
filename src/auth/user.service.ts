import {
  BadRequestException,
  HttpException,
  Injectable,
  InternalServerErrorException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class UserService {
  constructor(private prisma: PrismaService) {}

  async findOne(params: { email?: string; username?: string }) {
    try {
      if (!params.email && !params.username) {
        throw new BadRequestException(
          'Either email or username must be provided',
        );
      }

      return this.prisma.user.findFirst({
        where: {
          OR: [
            params.email ? { email: params.email } : undefined,
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
}
