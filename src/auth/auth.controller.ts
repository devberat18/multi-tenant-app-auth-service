import { Body, Controller, Post } from '@nestjs/common';
import { AuthLoginDto, AuthRefreshTokenDto, AuthRegisterDto } from './dto';
import { AuthService } from './auth.service';

@Controller('/v1/auth/')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('login')
  async login(@Body() body: AuthLoginDto) {
    return this.authService.login(body);
  }

  @Post('register')
  async register(@Body() body: AuthRegisterDto) {
    return this.authService.register(body);
  }

  @Post('/refresh')
  async refresh(@Body() body: AuthRefreshTokenDto) {
    return this.authService.refreshToken(body.refreshToken, body.userId);
  }
}
