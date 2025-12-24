import {
  BadRequestException,
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { UserDbService } from './user.db.service';
import * as bcrypt from 'bcrypt';
import { Prisma } from '@prisma/client';

@Injectable()
export class UserService {
  constructor(private usersDbService: UserDbService) {}

  async validateCredentials({ email, username, password }) {
    if ((!email && !username) || !password) {
      throw new BadRequestException('Invalid Credentials');
    }

    const identifier = email?.toLowerCase().trim() ?? username?.trim();

    const user = email
      ? await this.usersDbService.findOneByEmail(identifier)
      : await this.usersDbService.findOneByUsername(identifier);

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const verifyPassword = await bcrypt.compare(password, user.password);

    if (!verifyPassword) {
      throw new UnauthorizedException('Invalid credentials');
    }

    await this.usersDbService.updateLastLogin(user.id);

    return user;
  }

  async register({ email, username, phone_number, password }) {
    const normalizedEmail = email.toLowerCase().trim();
    const normalizedUsername = username.trim();

    const passwordHash = await bcrypt.hash(password, 10);

    try {
      return await this.usersDbService.create({
        email: normalizedEmail,
        username: normalizedUsername,
        password: passwordHash,
        role: 'user',
        phone_number: phone_number,
      });
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        throw new ConflictException('Email or username already exists');
      }
      throw error;
    }
  }
}
