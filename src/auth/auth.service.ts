import {
  BadRequestException,
  HttpException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { PrismaService } from 'src/prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { AuthDbService } from './auth.db.service';
import { RedisService } from 'src/redis/redis.service';
import * as crypto from 'crypto';

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private authDbService: AuthDbService,
    private redisService: RedisService,
    private prisma: PrismaService,
  ) {}

  async generateToken(
    userId: string,
    ip: string,
    userAgent: string,
    tokenType: 'refresh' | 'passwordReset',
  ) {
    const token = crypto.randomBytes(40).toString('hex');

    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 7);

    let key: string;
    let jsonStringify: any;
    let ttl: number;
    if (tokenType === 'refresh') {
      const hashedToken = await bcrypt.hash(token, 10);

      ttl = 60 * 60 * 24 * 7;

      const session = await this.prisma.token.create({
        data: {
          userId,
          refreshToken: hashedToken,
          ip,
          userDevice: userAgent,
          expiresAt,
          lastUsedAt: new Date(),
        },
      });
      key = `refresh_token:${token}`;
      jsonStringify = {
        userId,
        tokenId: session.id,
        ip,
        userAgent,
      };
    } else {
      ttl = 60 * 2; // 120 saniye

      key = `password_reset_token:${token}`;
      jsonStringify = {
        userId,
        ip,
        userAgent,
      };
    }

    await this.redisService.set(key, JSON.stringify(jsonStringify), ttl);

    return token;
  }

  async generateOtpCode(
    userId: string,
    ip: string,
    userAgent: string,
    resetType: 'email' | 'phone',
    email?: string,
    phone?: string,
  ) {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    let key: string;
    if (resetType === 'email') {
      if (!email)
        throw new BadRequestException('Email is required for email reset type');
      key = `password_reset:email:${email}`;
    } else {
      if (!phone)
        throw new BadRequestException(
          'Phone number is required for phone reset type',
        );
      key = `password_reset:phone:${phone}`;
    }

    await this.redisService.set(
      key,
      JSON.stringify({
        userId,
        otp,
        userAgent,
        ip,
      }),
      300,
    );

    return otp;
  }

  async login(
    params: { email?: string; username?: string; password: string },
    ip: string,
    userAgent: string,
  ) {
    try {
      if ((!params.email && !params.username) || !params.password) {
        throw new BadRequestException('All fields must be submitted.');
      }

      const user = await this.authDbService.findOne({
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

      await this.authDbService.updateLastLogin({ userId: user.id });

      const payload = {
        sub: user.id,
        email: user.email,
        role: user.role,
      };

      const accessToken = this.jwtService.sign(payload);
      const refreshToken = await this.generateToken(
        user.id,
        ip,
        userAgent,
        'refresh',
      );

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

      const user = await this.authDbService.createUser({
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

  async refreshToken(refreshToken: string) {
    try {
      const data = await this.redisService.get(`refresh_token:${refreshToken}`);

      if (!data)
        throw new UnauthorizedException('Invalid or expired refresh token');

      const parsed = JSON.parse(data);
      const userId = parsed.userId;

      const dbSession = await this.prisma.token.findUnique({
        where: { id: parsed.tokenId },
      });

      if (!dbSession) throw new UnauthorizedException('Session not found');

      const tokenMatch = await bcrypt.compare(
        refreshToken,
        dbSession.refreshToken,
      );
      if (!tokenMatch) throw new UnauthorizedException('Token mismatch');

      if (dbSession.revokedAt) throw new UnauthorizedException('Token revoked');

      if (dbSession.expiresAt < new Date())
        throw new UnauthorizedException('Token expired');

      const user = await this.authDbService.findById({ userId });

      if (!user) throw new UnauthorizedException('User not found');

      const payload = { sub: user.id, email: user.email, role: user.role };
      const accessToken = this.jwtService.sign(payload);

      await this.redisService.del(`refresh_token:${refreshToken}`);

      await this.prisma.token.update({
        where: { id: parsed.tokenId },
        data: { revokedAt: new Date() },
      });

      const newRefreshToken = await this.generateToken(
        user.id,
        parsed.ip,
        parsed.userAgent,
        'refresh',
      );

      return {
        accessToken,
        refreshToken: newRefreshToken,
      };
    } catch (error) {
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException('Unexpected error');
    }
  }

  async logoutCurrentSession(refreshToken: string) {
    try {
      const data = await this.redisService.get(`refresh_token:${refreshToken}`);

      if (!data)
        throw new UnauthorizedException('Invalid or expired refresh token');

      const parsed = JSON.parse(data);

      const dbSession = await this.prisma.token.findUnique({
        where: { id: parsed.tokenId },
      });

      if (!dbSession) throw new UnauthorizedException('Session not found');

      const tokenMatch = await bcrypt.compare(
        refreshToken,
        dbSession.refreshToken,
      );
      if (!tokenMatch) throw new UnauthorizedException('Token mismatch');

      await this.prisma.token.update({
        where: { id: parsed.tokenId },
        data: { revokedAt: new Date() },
      });

      await this.redisService.del(`refresh_token:${refreshToken}`);

      return { success: true };
    } catch (error) {
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException('Unexpected error');
    }
  }

  async logoutAllSession(userId: string) {
    try {
      await this.prisma.token.updateMany({
        where: { userId },
        data: { revokedAt: new Date() },
      });

      const stream = this.redisService.scanStream({
        match: 'refresh_token:*',
        count: 100,
      });

      stream.on('data', async (keys: string[]) => {
        for (const key of keys) {
          const data = await this.redisService.get(key);
          if (!data) continue;

          const parsed = JSON.parse(data);

          if (parsed.userId === userId) {
            await this.redisService.del(key);
          }
        }
      });

      return { success: true };
    } catch (error) {
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException('Unexpected error');
    }
  }

  async sendOtpCode(params: {
    ip: string;
    userAgent: string;
    resetType: 'email' | 'phone';
    email?: string;
    phone?: string;
  }) {
    try {
      const user = await this.authDbService.findOne({
        email: params.email,
        phone_number: params.phone,
      });

      if (!user) {
        throw new NotFoundException('User not found for given email/phone');
      }

      const otpCode = await this.generateOtpCode(
        user.id,
        params.ip,
        params.userAgent,
        params.resetType,
        params.email,
        params.phone,
      );

      console.log('otpCode');
      console.log(otpCode);
      console.log('otpCode');
      return true;
    } catch (error) {
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException('Unexpected error');
    }
  }

  async verifyOtpCode(params: {
    ip: string;
    userAgent: string;
    resetType: 'email' | 'phone';
    email?: string;
    phone?: string;
    otpCode: string;
  }) {
    try {
      const user = await this.authDbService.findOne({
        email: params.email,
        phone_number: params.phone,
      });

      if (!user) {
        throw new NotFoundException('User not found for given email/phone');
      }

      if (!params.otpCode) {
        throw new BadRequestException('otpCode is required');
      }

      let key: string;
      if (params.resetType === 'email') {
        if (!params.email)
          throw new BadRequestException(
            'Email is required for email reset type',
          );
        key = `password_reset:email:${params.email}`;
      } else {
        if (!params.phone)
          throw new BadRequestException(
            'Phone number is required for phone reset type',
          );
        key = `password_reset:phone:${params.phone}`;
      }

      console.log(key);

      const data = await this.redisService.get(key);
      if (!data) {
        throw new UnauthorizedException('Invalid or expired otpCode');
      }
      const parsed = JSON.parse(data);

      const attemptsKey = `password_reset_attempts:${user.id}`;
      const attempts = Number(
        (await this.redisService.get(attemptsKey)) || '0',
      );

      if (attempts >= 5) {
        throw new UnauthorizedException('Too many attempts, try again later');
      }

      if (parsed.otp !== params.otpCode) {
        await this.redisService.set(
          attemptsKey,
          (attempts + 1).toString(),
          900,
        );
        throw new UnauthorizedException('Invalid otpCode');
      }

      await this.redisService.del(attemptsKey);

      if (parsed.userAgent !== params.userAgent) {
        throw new UnauthorizedException('Otp code device mismatch');
      }

      if (parsed.ip !== params.ip) {
        throw new UnauthorizedException('Otp code ip mismatch');
      }

      if (parsed.otp !== params.otpCode) {
        throw new UnauthorizedException('Invalid otpCode');
      }

      console.log('Otp Kod Doğru ');

      const token = await this.generateToken(
        user.id,
        params.ip,
        params.userAgent,
        'passwordReset',
      );

      const passwordReset = await this.authDbService.createPasswordReset({
        ip: params.ip,
        token: token,
        userDevice: params.userAgent,
        userId: user.id,
      });

      if (!passwordReset) {
        throw new InternalServerErrorException(
          'Failed to create password reset record',
        );
      }

      await this.redisService.del(key);

      console.log(parsed);
      console.log(token);
      return token;
    } catch (error) {
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException('Unexpected error');
    }
  }

  async passwordReset(params: {
    passwordResetToken: string;
    password: string;
    rePassword: string;
    ip: string;
    userAgent: string;
  }) {
    try {
      const data = await this.redisService.get(
        `password_reset_token:${params.passwordResetToken}`,
      );

      if (!data) {
        throw new UnauthorizedException(
          'Invalid or expired password reset token',
        );
      }

      const parsed = JSON.parse(data);

      const user = await this.authDbService.findById({ userId: parsed.userId });

      if (!user) {
        throw new NotFoundException('User not found for given email/phone');
      }

      if (parsed.userAgent !== params.userAgent) {
        throw new UnauthorizedException('Password reset token device mismatch');
      }

      if (parsed.ip !== params.ip) {
        throw new UnauthorizedException('Password reset token ip mismatch');
      }

      if (params.password !== params.rePassword) {
        throw new BadRequestException('Passwords do not match');
      }

      await this.prisma.token.updateMany({
        where: { userId: parsed.userId, revokedAt: null },
        data: { revokedAt: new Date() },
      });

      const passwordResetData =
        await this.authDbService.getPasswordResetByUserAndToken({
          userId: parsed.userId,
          token: params.passwordResetToken,
        });

      if (!passwordResetData) {
        throw new NotFoundException('Data not found for given');
      }

      const hashedPassword = await bcrypt.hash(params.password, 10);

      await this.prisma.$transaction([
        this.prisma.user.update({
          where: { id: parsed.userId },
          data: { password: hashedPassword },
        }),
        this.prisma.passwordReset.update({
          where: { id: passwordResetData.id },
          data: { tokenUsed: true },
        }),
      ]);

      await this.redisService.del(
        `password_reset_token:${params.passwordResetToken}`,
      );
      return true;
    } catch (error) {
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException('Unexpected error');
    }
  }
}
