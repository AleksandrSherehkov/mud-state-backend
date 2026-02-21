import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';

import type { LoginDto } from '../dto/login.dto';
import { AuthRequestContext } from './types/auth-request-context';

import { UsersService } from 'src/users/users.service';
import { AuthSecurityService } from '../auth-security.service';
import { AuthTokensService } from '../auth-tokens.service';
import { AuthChallengeService } from '../auth-challenge.service';

import { normalizeIp } from 'src/common/net/ip-normalize';
import { AppLogger } from 'src/logger/logger.service';
import { hashId } from 'src/common/logging/log-sanitize';

@Injectable()
export class LoginUseCase {
  private readonly dummyPasswordHash: string;

  constructor(
    private readonly users: UsersService,
    private readonly authSecurity: AuthSecurityService,
    private readonly tokens: AuthTokensService,
    private readonly authChallenge: AuthChallengeService,
    private readonly config: ConfigService,
    private readonly logger: AppLogger,
  ) {
    this.logger.setContext(LoginUseCase.name);

    this.dummyPasswordHash =
      this.config.get<string>('AUTH_DUMMY_PASSWORD_HASH') ??
      '$2b$12$0IP/zdzyXTrX7AZRHVrTQeVvCAklfEeF8VCj0.9pJqlDmbqgth5Dq';
  }

  async execute(dto: LoginDto, ctx: AuthRequestContext) {
    const maybeIp = ctx.ip ? normalizeIp(ctx.ip) || undefined : undefined;

    const ua = ctx.userAgent?.trim() || 'unknown';
    const emailHash = hashId(dto.email.trim().toLowerCase());

    await this.authChallenge.assertSatisfiedOrThrow({
      identifierHash: emailHash,
      ip: maybeIp,
      headers: {
        nonce: ctx.challenge?.nonce,
        solution: ctx.challenge?.solution,
      },
    });

    const user = await this.users.findByEmail(dto.email);

    if (!user) {
      await bcrypt.compare(dto.password, this.dummyPasswordHash);

      await this.authSecurity.assertIdentifierNotLocked(emailHash);

      await this.authChallenge.recordLoginFail({
        identifierHash: emailHash,
        ip: maybeIp,
      });

      this.logger.warn('Login failed: unknown identifier', LoginUseCase.name, {
        event: 'auth.login.fail_unknown',
        emailHash,
      });

      return this.authSecurity.onUnknownLoginFailed({
        emailHash,
        ip: maybeIp,
        userAgent: ua,
      }) as never;
    }

    await this.authSecurity.assertNotLocked(user.id);

    const isValid = await bcrypt.compare(dto.password, user.password);

    if (!isValid) {
      await this.authChallenge.recordLoginFail({
        identifierHash: emailHash,
        ip: maybeIp,
      });

      return this.authSecurity.onLoginFailed({
        userId: user.id,
        ip: maybeIp,
        userAgent: ua,
      }) as never;
    }

    await this.authSecurity.onLoginSuccess(user.id);

    await this.authChallenge.clearOnSuccess({
      identifierHash: emailHash,
      ip: maybeIp,
    });

    this.logger.log('Login success', LoginUseCase.name, {
      event: 'auth.login.success',
      userId: user.id,
      role: user.role,
      emailHash,
    });

    return this.tokens.issueForUser({
      userId: user.id,
      email: user.email,
      role: user.role,
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      geo: ctx.geo,
    });
  }
}
