import { applyDecorators } from '@nestjs/common';
import { ApiExtension } from '@nestjs/swagger';
import { Role } from '@prisma/client';
import { buildDescription } from '../utils/description.builder';

export function ApiRolesAccess(
  roles: readonly Role[] | 'PUBLIC' | 'AUTHENTICATED',
  extra?: { sideEffects?: string | string[]; notes?: string | string[] },
) {
  const access = roles;

  return applyDecorators(
    ApiExtension(
      'x-access-policy',
      buildDescription({
        access,
        sideEffects: extra?.sideEffects,
        notes: extra?.notes,
      }),
    ),
  );
}
