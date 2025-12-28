import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { RedisService } from 'src/redis/redis.service';
import { UserDbService } from 'src/user/user.db.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    config: ConfigService,
    private redis: RedisService,
    private userDb: UserDbService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: config.get('jwt.secret'),
    });
  }

  async validate(payload: any) {
    const userId = payload.sub;
    const sid = payload.sid;

    if (!userId || !sid) throw new UnauthorizedException('Invalid token');

    const revoked = await this.redis.get(`session:revoked:${sid}`);
    if (revoked) throw new UnauthorizedException('Session revoked');

    const user = await this.userDb.findOneById(userId);
    if (!user) throw new UnauthorizedException('User not found');
    if (user.status === 'BANNED' || user.status === 'DEACTIVATED') {
      throw new UnauthorizedException(`Account is ${user.status}`);
    }
    return {
      userId: payload.sub,
      email: payload.email,
      role: payload.role,
      sid: payload.sid,
      status: payload.userStatus,
    };
  }
}
