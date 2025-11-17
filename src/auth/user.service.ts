import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class UserService {
  constructor(private prisma: PrismaService) {}

  async findOne(params: { email?: string; username?: string }) {
    try {
      if (!params.email || !params.username) {
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
      throw new InternalServerErrorException(error);
    }
  }
}
