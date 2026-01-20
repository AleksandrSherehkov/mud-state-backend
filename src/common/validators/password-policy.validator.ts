import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  ValidatorConstraint,
  ValidatorConstraintInterface,
} from 'class-validator';

type Policy = {
  min: number;
  max: number;
  requireUpper: boolean;
  requireDigit: boolean;
  requireSpecial: boolean;
};

const SPECIAL_RE = /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/;

@ValidatorConstraint({ name: 'PasswordPolicy', async: false })
@Injectable()
export class PasswordPolicyValidator implements ValidatorConstraintInterface {
  constructor(private readonly config: ConfigService) {}

  private policy(): Policy {
    const min = Number(this.config.get('PASSWORD_MIN_LENGTH') ?? 8);
    const max = Number(this.config.get('PASSWORD_MAX_LENGTH') ?? 72);

    return {
      min,
      max,
      requireUpper: Boolean(this.config.get('PASSWORD_REQUIRE_UPPERCASE')),
      requireDigit: Boolean(this.config.get('PASSWORD_REQUIRE_DIGIT')),
      requireSpecial: Boolean(this.config.get('PASSWORD_REQUIRE_SPECIAL')),
    };
  }

  validate(value: unknown): boolean {
    if (typeof value !== 'string') return false;

    const p = this.policy();
    const s = value;

    if (s.length < p.min || s.length > p.max) return false;
    if (p.requireUpper && !/[A-Z]/.test(s)) return false;
    if (p.requireDigit && !/\d/.test(s)) return false;
    if (p.requireSpecial && !SPECIAL_RE.test(s)) return false;

    return true;
  }

  defaultMessage(): string {
    const p = this.policy();

    const rules: string[] = [`від ${p.min} до ${p.max} символів`];
    if (p.requireUpper) rules.push('щонайменше 1 велика літера (A-Z)');
    if (p.requireDigit) rules.push('щонайменше 1 цифра (0-9)');
    if (p.requireSpecial) rules.push('щонайменше 1 спецсимвол');

    return `Пароль має містити: ${rules.join(', ')}.`;
  }
}
