import { Module } from '@nestjs/common';
import { PasswordPolicyValidator } from './password-policy.validator';

@Module({
  providers: [PasswordPolicyValidator],
  exports: [PasswordPolicyValidator],
})
export class ValidatorsModule {}
