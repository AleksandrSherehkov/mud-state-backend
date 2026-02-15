import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';

import type { LoginDto } from '../dto/login.dto';
import { AuthRequestContext } from './types/auth-request-context';

import { UsersService } from 'src/users/users.service';
import { AuthSecurityService } from '../auth-security.service';
import { AuthTokensService } from '../auth-tokens.service';

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
    private readonly config: ConfigService,
    private readonly logger: AppLogger,
  ) {
    this.logger.setContext(LoginUseCase.name);

    this.dummyPasswordHash =
      this.config.get<string>('AUTH_DUMMY_PASSWORD_HASH') ??
      '$2b$12$0IP/zdzyXTrX7AZRHVrTQeVvCAklfEeF8VCj0.9pJqlDmbqgth5Dq';
  }

  async execute(dto: LoginDto, ctx: AuthRequestContext) {
    const nip = ctx.ip ? normalizeIp(ctx.ip) : 'unknown';
    const ua = ctx.userAgent?.trim() || 'unknown';
    const emailHash = hashId(dto.email.toLowerCase());

    const user = await this.users.findByEmail(dto.email);
    if (!user) {
      // anti-enum timing dummy compare
      await bcrypt.compare(dto.password, this.dummyPasswordHash);

      this.logger.warn('Login failed: user not found', LoginUseCase.name, {
        event: 'auth.login.fail',
        reason: 'user_not_found',
        emailHash,
      });

      throw new UnauthorizedException('Невірний email або пароль');
    }

    await this.authSecurity.assertNotLocked(user.id);

    const isValid = await bcrypt.compare(dto.password, user.password);
    if (!isValid) {
      return this.authSecurity.onLoginFailed({
        userId: user.id,
        ip: nip,
        userAgent: ua,
      }) as never;
    }

    await this.authSecurity.onLoginSuccess(user.id);

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
