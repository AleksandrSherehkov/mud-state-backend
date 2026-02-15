import { Injectable } from '@nestjs/common';

import type { RegisterDto } from '../dto/register.dto';
import { AuthRequestContext } from './types/auth-request-context';

import { UsersService } from 'src/users/users.service';
import { AuthSecurityService } from '../auth-security.service';
import { AuthTokensService } from '../auth-tokens.service';

@Injectable()
export class RegisterUseCase {
  constructor(
    private readonly users: UsersService,
    private readonly authSecurity: AuthSecurityService,
    private readonly tokens: AuthTokensService,
  ) {}

  async execute(dto: RegisterDto, ctx: AuthRequestContext) {
    const user = await this.users.createUser(dto);

    await this.authSecurity.onLoginSuccess(user.id);

    const issued = await this.tokens.issueForUser({
      userId: user.id,
      email: user.email,
      role: user.role,
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      geo: ctx.geo,
    });

    return { ...user, ...issued };
  }
}
