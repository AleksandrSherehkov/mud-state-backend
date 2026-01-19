import { applyDecorators } from '@nestjs/common';
import { ApiOperation } from '@nestjs/swagger';
import { Role } from '@prisma/client';
import { buildDescription } from './description.builder';

export function ApiRolesAccess(
  roles: readonly Role[] | 'PUBLIC' | 'AUTHENTICATED',
  extra?: { sideEffects?: string | string[]; notes?: string | string[] },
) {
  const access = roles;

  return applyDecorators(
    ApiOperation({
      description: buildDescription({
        access,
        sideEffects: extra?.sideEffects,
        notes: extra?.notes,
      }),
    }),
  );
}
