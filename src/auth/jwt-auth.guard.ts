import {
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { RedisService } from 'src/redis/redis.service';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private redis: RedisService) {
    super();
  }
  async canActivate(ctx: ExecutionContext) {
    const ok = (await super.canActivate(ctx)) as boolean;
    if (!ok) return false;

    const req = ctx.switchToHttp().getRequest();
    const sid = req.user?.sid;

    if (!sid) throw new UnauthorizedException('Session missing');

    let revoked: string | null = null;
    try {
      revoked = await this.redis.get(`session:revoked:${sid}`);
    } catch {
      throw new UnauthorizedException('Auth temporarily unavailable');
    }
    if (revoked) throw new UnauthorizedException('Session revoked');

    return true;
  }
}
