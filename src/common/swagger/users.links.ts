import { applyDecorators } from '@nestjs/common';
import { ApiExtraModels, ApiOkResponse } from '@nestjs/swagger';

import { PublicUserDto } from 'src/users/dto/public-user.dto';

export const ApiUsersLinks = {
  getById200() {
    return applyDecorators(
      ApiExtraModels(PublicUserDto),
      ApiOkResponse({
        description: 'Знайдений користувач',
        type: PublicUserDto,
        links: {
          getByEmail: {
            operationId: 'users_getByEmail',
            description: 'Далі: знайти користувача за email',
          },
          update: {
            operationId: 'users_update',
            description: 'Далі: оновити користувача (ADMIN)',
          },
          delete: {
            operationId: 'users_delete',
            description: 'Далі: видалити користувача (ADMIN)',
          },
        },
      })
    );
  },

  getByEmail200() {
    return applyDecorators(
      ApiExtraModels(PublicUserDto),
      ApiOkResponse({
        description: 'Знайдений користувач',
        type: PublicUserDto,
        links: {
          getById: {
            operationId: 'users_getById',
            description: 'Далі: отримати користувача за ID',
          },
          update: {
            operationId: 'users_update',
            description: 'Далі: оновити користувача (ADMIN)',
          },
          delete: {
            operationId: 'users_delete',
            description: 'Далі: видалити користувача (ADMIN)',
          },
        },
      })
    );
  },

  update200() {
    return applyDecorators(
      ApiExtraModels(PublicUserDto),
      ApiOkResponse({
        description: 'Користувача оновлено',
        type: PublicUserDto,
        links: {
          getById: {
            operationId: 'users_getById',
            description: 'Далі: перевірити користувача за ID',
          },
          getByEmail: {
            operationId: 'users_getByEmail',
            description: 'Далі: перевірити користувача за email',
          },
          delete: {
            operationId: 'users_delete',
            description: 'Далі: видалити користувача (ADMIN)',
          },
        },
      })
    );
  },

  delete200() {
    return applyDecorators(
      ApiExtraModels(PublicUserDto),
      ApiOkResponse({
        description: 'Користувача видалено',
        type: PublicUserDto,
        links: {
          getById: {
            operationId: 'users_getById',
            description: 'Далі: перевірити, що користувача немає',
          },
          getByEmail: {
            operationId: 'users_getByEmail',
            description: 'Далі: перевірити, що користувача немає',
          },
        },
      })
    );
  },
} as const;
