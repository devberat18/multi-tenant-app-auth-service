import { Body, Controller, Post, Req, UseGuards } from '@nestjs/common';
import {
  AuthChangePasswordDto,
  AuthCreateOtpDto,
  AuthLoginDto,
  AuthRefreshTokenDto,
  AuthRegisterDto,
  AuthResetPasswordDto,
  AuthVerifyOtpCodeDto,
} from './dto';
import { AuthService } from './auth.service';
import {
  ApiBadRequestResponse,
  ApiBearerAuth,
  ApiCreatedResponse,
  ApiOkResponse,
  ApiOperation,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { JwtAuthGuard } from './jwt-auth.guard';

@Controller('v1/auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @ApiOperation({ summary: 'Login current user' })
  @ApiOkResponse({
    description: 'Returns accessToken and refreshToken',
    schema: {
      example: {
        accessToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        refreshToken: '123.9b4c7b0f0a...',
      },
    },
  })
  @ApiUnauthorizedResponse({ description: 'Invalid credentials' })
  @Post('login')
  async login(@Body() body: AuthLoginDto, @Req() req: any) {
    const userAgent = req.headers['user-agent'] || 'unknown';
    const xff = req.headers['x-forwarded-for'];
    const ip = typeof xff === 'string' ? xff.split(',')[0].trim() : req.ip;
    return this.authService.login(body, ip, userAgent);
  }

  @ApiOperation({ summary: 'Register new user' })
  @ApiCreatedResponse({
    description: 'User created',
    schema: { example: { success: true } },
  })
  @ApiBadRequestResponse({ description: 'Validation failed' })
  @Post('register')
  async register(@Body() body: AuthRegisterDto) {
    return this.authService.register(body);
  }

  @ApiOperation({ summary: 'Logout current session (refresh token)' })
  @ApiOkResponse({ schema: { example: { success: true } } })
  @ApiUnauthorizedResponse({ description: 'Invalid refresh token' })
  @Post('/logout')
  async logoutCurrentSession(@Body() body: AuthRefreshTokenDto) {
    return this.authService.logoutCurrentSessions(body.refreshToken);
  }

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Logout all sessions for current user' })
  @ApiOkResponse({ schema: { example: { success: true } } })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  @Post('/logout-all')
  async logoutAllSession(@Req() req: any) {
    return this.authService.logoutAllSessions(req.user.userId);
  }

  @ApiOperation({ summary: 'Refresh access token (rotate refresh token)' })
  @ApiOkResponse({
    description: 'Returns new accessToken and new refreshToken',
    schema: {
      example: {
        accessToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        refreshToken: '124.a7d9c2...',
      },
    },
  })
  @ApiUnauthorizedResponse({ description: 'Session expired / revoked' })
  @Post('/refresh')
  async refresh(@Body() body: AuthRefreshTokenDto, @Req() req: any) {
    const userAgent = req.headers['user-agent'] || 'unknown';
    const xff = req.headers['x-forwarded-for'];
    const ip = typeof xff === 'string' ? xff.split(',')[0].trim() : req.ip;
    return this.authService.refreshToken(body.refreshToken, ip, userAgent);
  }

  @ApiOperation({ summary: 'Send OTP (password reset flow)' })
  @ApiOkResponse({
    description: 'Always returns true (prevents account enumeration)',
    schema: { example: true },
  })
  @Post('/create-otp-code')
  async createOTPCode(@Body() body: AuthCreateOtpDto, @Req() req: any) {
    const userAgent = req.headers['user-agent'] || 'unknown';
    const xff = req.headers['x-forwarded-for'];
    const ip = typeof xff === 'string' ? xff.split(',')[0].trim() : req.ip;
    return this.authService.sendOtpCode(
      ip,
      userAgent,
      body.resetType,
      body.email,
      body.phone_number,
    );
  }

  @ApiOperation({ summary: 'Verify OTP and issue password reset token' })
  @ApiOkResponse({
    description: 'Returns password reset token (raw)',
    schema: { example: { passwordResetToken: 'a1b2c3...' } },
  })
  @ApiUnauthorizedResponse({
    description: 'Invalid/expired OTP or too many attempts',
  })
  @Post('verify-otp-code')
  async verifyOtp(@Body() body: AuthVerifyOtpCodeDto, @Req() req: any) {
    const userAgent = req.headers['user-agent'] || 'unknown';
    const xff = req.headers['x-forwarded-for'];
    const ip = typeof xff === 'string' ? xff.split(',')[0].trim() : req.ip;
    return this.authService.verifyOtpCode(
      ip,
      userAgent,
      body.resetType,
      body.otpCode,
      body.email,
      body.phone_number,
    );
  }

  @ApiOperation({ summary: 'Reset password using password reset token' })
  @ApiOkResponse({ schema: { example: true } })
  @ApiUnauthorizedResponse({ description: 'Invalid/expired token' })
  @Post('reset-password')
  async resetPassword(@Body() body: AuthResetPasswordDto) {
    return this.authService.passwordReset(
      body.passwordResetToken,
      body.password,
      body.rePassword,
    );
  }

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Change password (requires current password)' })
  @ApiOkResponse({ schema: { example: true } })
  @ApiUnauthorizedResponse({
    description: 'Invalid credentials / Unauthorized',
  })
  @Post('change-password')
  async changePassword(@Body() body: AuthChangePasswordDto, @Req() req: any) {
    return this.authService.changePassword(
      req.user.userId,
      body.oldPassword,
      body.password,
      body.rePassword,
    );
  }
  // TO DO :  Me, Session list + session revoke, Account delete/deactivate, Admin user list, ban/unban, role update
}
