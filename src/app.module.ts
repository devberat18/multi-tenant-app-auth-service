import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AppConfigModule } from './app-config/app-config.module';
import { RedisModule } from './redis/redis.module';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';
import { TokenModule } from './token/token.module';
import { OtpModule } from './otp/otp.module';
import { EventsModule } from './events/events.module';

@Module({
  imports: [
    AppConfigModule,
    RedisModule,
    PrismaModule,
    AuthModule,
    UserModule,
    TokenModule,
    OtpModule,
    EventsModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
