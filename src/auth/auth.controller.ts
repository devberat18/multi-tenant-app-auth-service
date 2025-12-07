import { Body, Controller, Post, Req, UseGuards } from '@nestjs/common';
import {
  AuthLoginDto,
  AuthRefreshTokenDto,
  AuthRegisterDto,
  AuthCreateOtpDto,
  AuthVerifyOtpCodeDto,
  AuthResetPasswordDto,
} from './dto';
import { AuthService } from './auth.service';
import { ApiOperation } from '@nestjs/swagger';
import { JwtAuthGuard } from './jwt-auth.guard';

@Controller('v1/auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @ApiOperation({ summary: 'Login current user' })
  @Post('login')
  async login(@Body() body: AuthLoginDto, @Req() req: any) {
    const userAgent = req.headers['user-agent'] || 'unknown';
    const ip =
      (req.headers['x-forwarded-for'] as string) ||
      req.ip ||
      (req.connection as any)?.remoteAddress ||
      'unknown';
    return this.authService.login(body, ip, userAgent);
  }

  @ApiOperation({ summary: 'Register new user' })
  @Post('register')
  async register(@Body() body: AuthRegisterDto) {
    return this.authService.register(body);
  }

  @ApiOperation({ summary: 'Refresh Token' })
  @Post('/refresh')
  async refresh(@Body() body: AuthRefreshTokenDto) {
    return this.authService.refreshToken(body.refreshToken);
  }

  @ApiOperation({ summary: 'Logout current session' })
  @Post('/log-out')
  async logoutCurrentSession(@Body() body: AuthRefreshTokenDto) {
    return this.authService.logoutCurrentSession(body.refreshToken);
  }

  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Logout all session' })
  @Post('/log-out-all')
  async logoutAllSession(@Body() body: AuthRefreshTokenDto, @Req() req: any) {
    return this.authService.logoutAllSession(req.user.userId);
  }

  @ApiOperation({ summary: 'Create Otp Code' })
  @Post('/create-otp-code')
  async createOTPCode(@Body() body: AuthCreateOtpDto, @Req() req: any) {
    const userAgent = req.headers['user-agent'] || 'unknown';
    const ip =
      (req.headers['x-forwarded-for'] as string) ||
      req.ip ||
      (req.connection as any)?.remoteAddress ||
      'unknown';
    return this.authService.sendOtpCode({
      ip: ip,
      userAgent: userAgent,
      resetType: body.resetType,
      email: body.email,
      phone: body.phone_number,
    });
  }

  @ApiOperation({ summary: 'Verify Otp Code' })
  @Post('verify-otp-code')
  async verifyOtp(@Body() body: AuthVerifyOtpCodeDto, @Req() req: any) {
    const userAgent = req.headers['user-agent'] || 'unknown';
    const ip =
      (req.headers['x-forwarded-for'] as string) ||
      req.ip ||
      (req.connection as any)?.remoteAddress ||
      'unknown';
    return this.authService.verifyOtpCode({
      ip: ip,
      userAgent: userAgent,
      resetType: body.resetType,
      email: body.email,
      phone: body.phone_number,
      otpCode: body.otpCode,
    });
  }

  @ApiOperation({ summary: 'Password Reset' })
  @Post('reset-password')
  async resetPassword(@Body() body: AuthResetPasswordDto, @Req() req: any) {
    const userAgent = req.headers['user-agent'] || 'unknown';
    const ip =
      (req.headers['x-forwarded-for'] as string) ||
      req.ip ||
      (req.connection as any)?.remoteAddress ||
      'unknown';
    return this.authService.passwordReset({
      ip: ip,
      userAgent: userAgent,
      password: body.password,
      rePassword: body.rePassword,
      passwordResetToken: body.passwordResetToken,
    });
  }
}
