import { Module } from '@nestjs/common';

import { AuthInfrastructureModule } from './modules/auth-infrastructure.module';
import { AuthUseCasesModule } from './modules/auth-use-cases.module';

@Module({
  imports: [AuthInfrastructureModule, AuthUseCasesModule],
  exports: [AuthInfrastructureModule, AuthUseCasesModule],
})
export class AuthCoreModule {}
