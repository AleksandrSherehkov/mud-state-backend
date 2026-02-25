import { Module } from '@nestjs/common';

import { AuthInfrastructureModule } from './auth-infrastructure.module';
import { AuthRefreshModule } from './auth-refresh.module';

import { RegisterUseCase } from '../../use-cases/register.use-case';
import { LoginUseCase } from '../../use-cases/login.use-case';
import { RefreshUseCase } from '../../use-cases/refresh.use-case';
import { LogoutUseCase } from '../../use-cases/logout.use-case';
import { GetMeUseCase } from '../../use-cases/get-me.use-case';

@Module({
  imports: [AuthInfrastructureModule, AuthRefreshModule],
  providers: [
    RegisterUseCase,
    LoginUseCase,
    RefreshUseCase,
    LogoutUseCase,
    GetMeUseCase,
  ],
  exports: [
    RegisterUseCase,
    LoginUseCase,
    RefreshUseCase,
    LogoutUseCase,
    GetMeUseCase,
  ],
})
export class AuthUseCasesModule {}
