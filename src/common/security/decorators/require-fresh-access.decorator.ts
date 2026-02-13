import { SetMetadata } from '@nestjs/common';

export const FRESH_ACCESS_MAX_AGE_SEC_KEY = 'fresh_access_max_age_sec';

export function RequireFreshAccess(
  maxAgeSec = 120,
): MethodDecorator & ClassDecorator {
  return SetMetadata(FRESH_ACCESS_MAX_AGE_SEC_KEY, maxAgeSec);
}
