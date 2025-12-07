import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsIn,
  IsNotEmpty,
  IsString,
  ValidateIf,
} from 'class-validator';

export class AuthLoginDto {
  @ApiProperty({ example: 'jhone_doe', description: 'Username' })
  @IsString()
  username?: string;

  @ApiProperty({ example: 'jhonedoe@mail.com', description: 'User email' })
  email?: string;

  @ApiProperty({ example: '', description: 'User passsword' })
  @IsString()
  @IsNotEmpty()
  password: string;
}

export class AuthRegisterDto {
  @ApiProperty({ example: 'jhone_doe', description: 'Username' })
  @IsString()
  @IsNotEmpty()
  username: string;

  @ApiProperty({ example: 'jhonedoe@mail.com', description: 'User email' })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({
    example: '05676787834',
    description: 'User Phone Number',
  })
  @IsString()
  @IsNotEmpty()
  phone_number: string;

  @ApiProperty({ example: '', description: 'User passsword' })
  @IsString()
  @IsNotEmpty()
  password: string;

  @ApiProperty({ example: '', description: 'User repasssword' })
  @IsString()
  @IsNotEmpty()
  rePassword: string;
}

export class AuthRefreshTokenDto {
  @IsNotEmpty()
  refreshToken: string;
}

export class AuthCreateOtpDto {
  @IsIn(['email', 'phone'])
  resetType: 'email' | 'phone';

  @ApiProperty({ example: 'jhonedoe@mail.com', description: 'User email' })
  @ValidateIf((o) => o.resetType === 'email')
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({
    example: '05676787834',
    description: 'User Phone Number',
  })
  @ValidateIf((o) => o.resetType === 'phone')
  @IsString()
  @IsNotEmpty()
  phone_number: string;
}

export class AuthVerifyOtpCodeDto {
  @IsIn(['email', 'phone'])
  resetType: 'email' | 'phone';

  @ApiProperty({ example: 'jhonedoe@mail.com', description: 'User email' })
  @ValidateIf((o) => o.resetType === 'email')
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({
    example: '05676787834',
    description: 'User Phone Number',
  })
  @ValidateIf((o) => o.resetType === 'phone')
  @IsString()
  @IsNotEmpty()
  phone_number: string;

  @IsNotEmpty()
  otpCode: string;
}

export class AuthResetPasswordDto {
  @ApiProperty({ example: '', description: 'Password Reset Token' })
  @IsNotEmpty()
  passwordResetToken: string;

  @ApiProperty({ example: '', description: 'User passsword' })
  @IsNotEmpty()
  password: string;

  @ApiProperty({ example: '', description: 'User repasssword' })
  @IsNotEmpty()
  rePassword: string;
}
