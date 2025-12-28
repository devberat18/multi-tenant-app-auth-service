import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';

@Injectable()
export class RequireActiveGuard implements CanActivate {
  canActivate(ctx: ExecutionContext) {
    const req = ctx.switchToHttp().getRequest();
    const status = req.user?.status;
    if (status !== 'ACTIVE')
      throw new ForbiddenException('Verification required');
    return true;
  }
}
