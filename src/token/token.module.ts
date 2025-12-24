import { Module } from '@nestjs/common';
import { TokenService } from './token.service';
import { TokenDbService } from './token.db.service';

@Module({
  providers: [TokenService, TokenDbService],
  exports: [TokenService, TokenDbService],
})
export class TokenModule {}
