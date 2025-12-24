import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsEmail,
  IsIn,
  IsNotEmpty,
  IsString,
  Matches,
  MaxLength,
  MinLength,
  ValidateIf,
} from 'class-validator';

export class AuthLoginDto {
  @ApiPropertyOptional({
    example: 'jhone_doe',
    description: 'Username (required if email is not provided)',
  })
  @ValidateIf((o) => !o.email)
  @IsString()
  @IsNotEmpty()
  username?: string;

  @ApiPropertyOptional({
    example: 'jhonedoe@mail.com',
    description: 'Email (required if username is not provided)',
  })
  @ValidateIf((o) => !o.username)
  @IsEmail()
  email?: string;

  @ApiProperty({
    example: 'StrongPass1!',
    description: 'User password',
  })
  @IsString()
  @IsNotEmpty()
  password: string;
}

export class AuthRegisterDto {
  @ApiProperty({
    example: 'jhone_doe',
    description: 'Unique username',
  })
  @IsString()
  @IsNotEmpty()
  username: string;

  @ApiProperty({
    example: 'jhonedoe@mail.com',
    description: 'Unique email address',
  })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({
    example: '05676787834',
    description: 'Phone number',
  })
  @IsString()
  @IsNotEmpty()
  phone_number: string;

  @ApiProperty({
    example: 'StrongPass1!',
    description:
      'Password (min 8 chars, uppercase, lowercase, number, special char)',
  })
  @IsString()
  @IsNotEmpty()
  password: string;

  @ApiProperty({
    example: 'StrongPass1!',
    description: 'Password confirmation',
  })
  @IsString()
  @IsNotEmpty()
  rePassword: string;
}

export class AuthRefreshTokenDto {
  @ApiProperty({
    example: '12.9b4c7b0f0a3c1e...',
    description: 'Refresh token in format: <sessionId>.<token>',
  })
  @IsNotEmpty()
  refreshToken: string;
}

export class AuthCreateOtpDto {
  @ApiProperty({
    example: 'email',
    enum: ['email', 'phone'],
    description: 'OTP channel',
  })
  @IsIn(['email', 'phone'])
  resetType: 'email' | 'phone';

  @ApiPropertyOptional({
    example: 'jhonedoe@mail.com',
    description: 'Required if resetType=email',
  })
  @ValidateIf((o) => o.resetType === 'email')
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiPropertyOptional({
    example: '05676787834',
    description: 'Required if resetType=phone',
  })
  @ValidateIf((o) => o.resetType === 'phone')
  @IsString()
  @IsNotEmpty()
  phone_number: string;
}

export class AuthVerifyOtpCodeDto {
  @ApiProperty({
    example: 'email',
    enum: ['email', 'phone'],
  })
  @IsIn(['email', 'phone'])
  resetType: 'email' | 'phone';

  @ApiPropertyOptional({
    example: 'jhonedoe@mail.com',
  })
  @ValidateIf((o) => o.resetType === 'email')
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiPropertyOptional({
    example: '05676787834',
  })
  @ValidateIf((o) => o.resetType === 'phone')
  @IsString()
  @IsNotEmpty()
  phone_number: string;

  @ApiProperty({
    example: '123456',
    description: '6-digit OTP code',
  })
  @IsString()
  @IsNotEmpty()
  otpCode: string;
}

export class AuthResetPasswordDto {
  @ApiProperty({
    example: 'a1b2c3d4e5f6...',
    description: 'Password reset token (raw)',
  })
  @IsNotEmpty()
  passwordResetToken: string;

  @ApiProperty({
    example: 'StrongPass1!',
    description:
      'New password (min 8 chars, uppercase, lowercase, number, special char)',
  })
  @IsNotEmpty()
  password: string;

  @ApiProperty({
    example: 'StrongPass1!',
    description: 'Password confirmation',
  })
  @IsNotEmpty()
  rePassword: string;
}
export class AuthChangePasswordDto {
  @ApiProperty({
    example: 'OldPass1!',
    description: 'Current password',
  })
  @IsString()
  @IsNotEmpty()
  oldPassword: string;

  @IsString()
  @MinLength(8)
  @MaxLength(72)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).+$/, {
    message:
      'Password must contain uppercase, lowercase, number and special character',
  })
  @IsNotEmpty()
  password: string;

  @ApiProperty({
    example: 'NewStrongPass1!',
    description: 'Password confirmation',
  })
  @IsString()
  @IsNotEmpty()
  rePassword: string;
}
