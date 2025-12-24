import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { RedisService } from 'src/redis/redis.service';
import * as crypto from 'crypto';

@Injectable()
export class OtpService {
  constructor(private redisService: RedisService) {}

  private hashIssueOtp(otp: string): string {
    return crypto.createHash('sha256').update(otp).digest('hex');
  }

  async issueOtp(
    userId: string,
    ip: string,
    userAgent: string,
    resetType: 'email' | 'phone',
    params: {
      email?: string;
      phone_number?: string;
    },
  ) {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedOtp = this.hashIssueOtp(otp);
    const emailNorm = params.email?.toLowerCase().trim();
    const phoneNorm = params.phone_number?.trim();

    if (
      (resetType === 'email' && !emailNorm) ||
      (resetType === 'phone' && !phoneNorm)
    ) {
      throw new BadRequestException('Missing parameter');
    }
    const identifier = resetType === 'email' ? emailNorm : phoneNorm;

    const key =
      resetType === 'email'
        ? `otp:pwdreset:email:${identifier}`
        : `otp:pwdreset:phone:${identifier}`;

    await this.redisService.set(
      key,
      JSON.stringify({
        userId,
        hashedOtp,
        userAgent,
        ip,
      }),
      300,
    );

    return otp;
  }

  async verifyOtp(
    resetType: 'email' | 'phone',
    otpCode: string,
    userId: string,
    params: { email?: string; phone_number?: string },
  ) {
    const incomingHashedOtp = this.hashIssueOtp(otpCode);

    const emailNorm = params.email?.toLowerCase().trim();
    const phoneNorm = params.phone_number?.trim();

    if (
      (resetType === 'email' && !emailNorm) ||
      (resetType === 'phone' && !phoneNorm)
    ) {
      throw new BadRequestException('Missing parameter');
    }
    const identifier = resetType === 'email' ? emailNorm : phoneNorm;

    const key =
      resetType === 'email'
        ? `otp:pwdreset:email:${identifier}`
        : `otp:pwdreset:phone:${identifier}`;

    const data = await this.redisService.get(key);

    if (!data) {
      throw new UnauthorizedException('Invalid or expired otpCode');
    }

    const parsed = JSON.parse(data);

    const attemptsKey = `otp:pwdreset:attempts:${resetType}:${identifier}`;

    const attempts = Number((await this.redisService.get(attemptsKey)) || '0');

    if (attempts >= 5) {
      throw new UnauthorizedException('Too many attempts, try again later');
    }

    if (incomingHashedOtp !== parsed.hashedOtp) {
      await this.redisService.set(attemptsKey, (attempts + 1).toString(), 900);
      throw new UnauthorizedException('Invalid otpCode');
    }

    await this.redisService.del(attemptsKey);
    await this.redisService.del(key);

    return true;
  }
}
