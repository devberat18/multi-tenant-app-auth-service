import { Body, Controller, Post } from '@nestjs/common';
import { AuthLoginDto } from './dto';

@Controller('api/v1/auth')
export class AuthController {
  @Post('/login')
  async login(@Body() body: AuthLoginDto) {}
}
