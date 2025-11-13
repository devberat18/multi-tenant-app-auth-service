import { Module, Global } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis, { RedisOptions } from 'ioredis';
import { RedisService } from './redis.service';

@Global()
@Module({
  providers: [
    {
      provide: 'REDIS_CLIENT',
      inject: [ConfigService],
      useFactory: (config: ConfigService) => {
        const redisConfig: RedisOptions = {
          host: config.get<string>('redis.host'),
          port: config.get<number>('redis.port'),
          db: config.get<number>('redis.db') ?? 0,
          password: config.get<string>('redis.password') || undefined,

          retryStrategy: (times: number) => {
            const delay = Math.min(times * 50, 2000);
            return delay;
          },

          connectTimeout: 5000,
        };

        return new Redis(redisConfig);
      },
    },

    RedisService,
  ],

  exports: ['REDIS_CLIENT', RedisService],
})
export class RedisModule {}
