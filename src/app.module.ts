import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AppConfigModule } from './app-config/app-config.module';
import { DatabaseModule } from './database/database.module';
import { RedisModule } from './redis/redis.module';

@Module({
  imports: [AppConfigModule, DatabaseModule, RedisModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
