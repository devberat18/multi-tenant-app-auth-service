import { Module } from '@nestjs/common';
import { UserService } from './user.service';
import { UserDbService } from './user.db.service';
import { PasswordService } from './password.service';
import { PasswordDbService } from './password.db.service';

@Module({
  providers: [UserService, UserDbService, PasswordService, PasswordDbService],
  exports: [UserDbService, UserService, PasswordService, PasswordDbService],
})
export class UserModule {}
