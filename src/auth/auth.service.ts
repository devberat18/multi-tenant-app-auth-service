import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UserService } from 'src/user/user.service';
import { TokenService } from 'src/token/token.service';
import { UserDbService } from 'src/user/user.db.service';
import { OtpService } from 'src/otp/otp.service';
import { PasswordService } from 'src/user/password.service';
import { PasswordDbService } from 'src/user/password.db.service';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UserService,
    private passwordService: PasswordService,
    private passwordDbService: PasswordDbService,
    private userDbService: UserDbService,
    private tokensService: TokenService,
    private otpService: OtpService,
    private jwtService: JwtService,
  ) {}

  async login(params, ip: string, userAgent: string) {
    const user = await this.usersService.validateCredentials(params);
    const { refreshToken, sessionId } = await this.tokensService.issueSession(
      user.id,
      ip,
      userAgent,
    );

    const accessToken = this.jwtService.sign({
      sub: user.id,
      email: user.email,
      role: user.role,
      sid: sessionId,
    });
    return { accessToken, refreshToken };
  }

  async register(params) {
    await this.usersService.register(params);
    return {
      success: true,
    };
  }

  async logoutCurrentSessions(refreshToken: string) {
    return await this.tokensService.logutCurrentSession(refreshToken);
  }

  async logoutAllSessions(userId: string) {
    return await this.tokensService.logoutAllSessions(userId);
  }

  async refreshToken(refreshToken: string, ip: string, userAgent: string) {
    const { userId, newRefreshToken, newSessionId } =
      await this.tokensService.refreshSession(refreshToken, ip, userAgent);

    const user = await this.userDbService.findOneById(userId);
    if (!user) throw new UnauthorizedException('User not found');

    const accessToken = this.jwtService.sign({
      sub: user.id,
      email: user.email,
      role: user.role,
      sid: newSessionId,
    });

    return { accessToken, refreshToken: newRefreshToken };
  }

  async sendOtpCode(
    ip: string,
    userAgent: string,
    resetType: 'email' | 'phone',
    email?: string,
    phone_number?: string,
  ) {
    const emailNorm = email?.toLowerCase().trim();
    const phoneNorm = phone_number?.trim();

    if (
      (resetType === 'email' && !emailNorm) ||
      (resetType === 'phone' && !phoneNorm)
    ) {
      throw new BadRequestException('Missing parameter');
    }
    const identifier = resetType === 'email' ? emailNorm : phoneNorm;

    const user =
      resetType === 'email'
        ? await this.userDbService.findOneByEmail(identifier)
        : await this.userDbService.findOneByPhoneNumber(identifier);

    if (!user) {
      return true;
    }

    const otpCode =
      resetType === 'email'
        ? await this.otpService.issueOtp(user.id, ip, userAgent, resetType, {
            email: emailNorm,
          })
        : await this.otpService.issueOtp(user.id, ip, userAgent, resetType, {
            phone_number: phoneNorm,
          });

    console.log('OTP CODE : ');
    console.log(otpCode);
    return true;
  }

  async verifyOtpCode(
    ip: string,
    userAgent: string,
    resetType: 'email' | 'phone',
    otpCode: string,
    email?: string,
    phone_number?: string,
  ) {
    const emailNorm = email?.toLowerCase().trim();
    const phoneNorm = phone_number?.trim();

    if (
      (resetType === 'email' && !emailNorm) ||
      (resetType === 'phone' && !phoneNorm)
    ) {
      throw new BadRequestException('Missing parameter');
    }

    const identifier = resetType === 'email' ? emailNorm : phoneNorm;

    const user =
      resetType === 'email'
        ? await this.userDbService.findOneByEmail(identifier)
        : await this.userDbService.findOneByPhoneNumber(identifier);

    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (!otpCode) {
      throw new BadRequestException('otpCode is required');
    }

    const verifyOtpCode =
      resetType === 'email'
        ? await this.otpService.verifyOtp(resetType, otpCode, user.id, {
            email: emailNorm,
          })
        : await this.otpService.verifyOtp(resetType, otpCode, user.id, {
            phone_number: phoneNorm,
          });

    if (!verifyOtpCode) {
      throw new BadRequestException('');
    }

    const passwordResetToken =
      await this.passwordService.createPasswordResetToken(
        user.id,
        ip,
        userAgent,
      );

    const passwordReset = await this.passwordDbService.create({
      ip: ip,
      token: passwordResetToken.hashedToken,
      userDevice: userAgent,
      user: { connect: { id: user.id } },
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 2 * 60 * 1000),
    });

    if (!passwordReset) {
      throw new BadRequestException('Failed to create password reset record');
    }

    return passwordResetToken.token;
  }

  async passwordReset(
    passwordResetToken: string,
    password: string,
    rePassword: string,
  ) {
    return this.passwordService.paswordReset(
      passwordResetToken,
      password,
      rePassword,
    );
  }

  async changePassword(
    userId: string,
    oldPassword: string,
    password: string,
    rePassword: string,
  ) {
    return await this.passwordService.changePassword(
      userId,
      oldPassword,
      password,
      rePassword,
    );
  }
}
