import {
  BadRequestException,
  HttpException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { UserService } from './user.service';
import { RedisService } from 'src/redis/redis.service';
import * as crypto from 'crypto';

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private userService: UserService,
    private redisService: RedisService,
  ) {}

  async generateRefreshToken(userId: string) {
    const token = crypto.randomBytes(40).toString('hex');
    const hashed = await bcrypt.hash(token, 10);

    await this.redisService.set(
      `refresh_token:${userId}`,
      hashed,
      60 * 60 * 24 * 7,
    );

    return token;
  }

  async login(params: { email?: string; username?: string; password: string }) {
    try {
      if ((!params.email && !params.username) || !params.password) {
        throw new BadRequestException('All fields must be submitted.');
      }

      const user = await this.userService.findOne({
        email: params.email,
        username: params.username,
      });

      if (!user) {
        throw new NotFoundException('User Not Found');
      }

      const isMatch = await bcrypt.compare(params.password, user.password);

      if (!isMatch) {
        throw new UnauthorizedException('Invalid credentials');
      }

      await this.userService.updateLastLogin({ userId: user.id });

      const payload = {
        sub: user.id,
        email: user.email,
        role: user.role,
      };

      const accessToken = this.jwtService.sign(payload);
      const refreshToken = await this.generateRefreshToken(user.id);

      return { accessToken, refreshToken };
    } catch (error) {
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException('Unexpected error');
    }
  }

  async register(params: {
    username: string;
    email: string;
    phone_number: string;
    password: string;
    rePassword: string;
  }) {
    try {
      if (!params?.password || !params?.rePassword) {
        throw new BadRequestException('All fields must be submitted.');
      }

      if (params.password !== params.rePassword) {
        throw new BadRequestException(
          'The passwords entered must be the same.',
        );
      }
      const hashedPassword = await bcrypt.hash(params.password, 10);

      const user = await this.userService.createUser({
        email: params.email,
        username: params.username,
        phone_number: params.phone_number,
        password: hashedPassword,
      });

      if (!user) {
        throw new BadRequestException('User could not be created');
      }
      return user;
    } catch (error) {
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException('Unexpected error');
    }
  }

  async refreshToken(refreshToken: string, userId: string) {
    try {
      const stored = await this.redisService.get(`refresh_token:${userId}`);

      if (!stored) {
        throw new UnauthorizedException('Refresh token expired or missing');
      }

      const isMatch = await bcrypt.compare(refreshToken, stored);

      if (!isMatch) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      const user = await this.userService.findById({ userId: userId });
      if (!user) throw new UnauthorizedException('User not found');

      const payload = {
        sub: user.id,
        email: user.email,
        role: user.role,
      };

      const accessToken = this.jwtService.sign(payload);

      // İstersen refresh token'ı da yenileyebiliriz
      const newRefreshToken = await this.generateRefreshToken(user.id);

      return {
        accessToken,
        refreshToken: newRefreshToken,
      };
    } catch (error) {
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException('Failed to refresh token');
    }
  }
}
