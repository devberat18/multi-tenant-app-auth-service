import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class AuthLoginDto {
  @IsString()
  username?: string;

  @IsEmail()
  email?: string;

  @IsString()
  @IsNotEmpty()
  password: string;
}
