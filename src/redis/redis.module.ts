import { Module, Global } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Redis } from 'ioredis';
import { RedisService } from './redis.service';

@Global()
@Module({
  providers: [
    {
      provide: 'REDIS_CLIENT',
      useFactory: (configService: ConfigService) => {
        const redisConfig: any = {
          host: configService.get<string>('redis.host'),
          port: configService.get<number>('redis.port'),
        };

        const password = configService.get<string>('redis.password');
        if (password) {
          redisConfig.password = password;
        }

        return new Redis(redisConfig);
      },
      inject: [ConfigService],
    },
    RedisService,
  ],
  exports: [RedisService, 'REDIS_CLIENT'],
})
export class RedisModule {}

