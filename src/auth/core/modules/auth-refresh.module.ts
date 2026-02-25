import { Module } from '@nestjs/common';

import { AuthInfrastructureModule } from './auth-infrastructure.module';

import { RefreshVerifier } from '../../use-cases/refresh/refresh.verifier';
import { RefreshRotationService } from '../../use-cases/refresh/refresh.rotation.service';
import { RefreshIncidentResponseService } from '../../use-cases/refresh/refresh.incident-response.service';

@Module({
  imports: [AuthInfrastructureModule],
  providers: [
    RefreshVerifier,
    RefreshRotationService,
    RefreshIncidentResponseService,
  ],
  exports: [
    RefreshVerifier,
    RefreshRotationService,
    RefreshIncidentResponseService,
  ],
})
export class AuthRefreshModule {}
