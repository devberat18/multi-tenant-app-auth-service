import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class AuthLoginDto {
  @IsString()
  username?: string;

  email?: string;

  @IsString()
  @IsNotEmpty()
  password: string;
}

export class AuthRegisterDto {
  @IsString()
  @IsNotEmpty()
  username: string;

  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  phone_number: string;

  @IsString()
  @IsNotEmpty()
  password: string;

  @IsString()
  @IsNotEmpty()
  rePassword: string;
}

export class AuthRefreshTokenDto {
  @IsNotEmpty()
  refreshToken: string;

  @IsNotEmpty()
  userId: string;
}
