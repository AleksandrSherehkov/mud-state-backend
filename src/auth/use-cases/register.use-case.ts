import { Injectable } from '@nestjs/common';

import type { RegisterDto } from '../dto/register.dto';
import { AuthRequestContext } from './types/auth-request-context';

import { UsersService } from 'src/users/users.service';
import { AuthSecurityService } from '../auth-security.service';
import { AuthTokensService } from '../auth-tokens.service';
import { AuthChallengeService } from '../auth-challenge.service';

import { normalizeIp } from 'src/common/net/ip-normalize';
import { hashId } from 'src/common/logging/log-sanitize';

@Injectable()
export class RegisterUseCase {
  constructor(
    private readonly users: UsersService,
    private readonly authSecurity: AuthSecurityService,
    private readonly tokens: AuthTokensService,
    private readonly authChallenge: AuthChallengeService,
  ) {}

  async execute(dto: RegisterDto, ctx: AuthRequestContext) {
    const maybeIp = ctx.ip ? normalizeIp(ctx.ip) || undefined : undefined;
    const emailHash = hashId(dto.email.trim().toLowerCase());

    await this.authChallenge.assertRegisterSatisfiedOrThrow({
      identifierHash: emailHash,
      ip: maybeIp,
      headers: {
        nonce: ctx.challenge?.nonce,
        solution: ctx.challenge?.solution,
      },
    });

    const user = await this.users.createUser(dto);

    await this.authSecurity.onLoginSuccess(user.id);

    const issued = await this.tokens.issueForUser({
      userId: user.id,
      email: user.email,
      role: user.role,
      tokenVersion: 0,
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      geo: ctx.geo,
    });

    return { ...user, ...issued };
  }
}
