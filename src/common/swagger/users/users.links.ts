import { applyDecorators } from '@nestjs/common';
import { ApiExtraModels, ApiOkResponse } from '@nestjs/swagger';

import { PublicUserDto } from 'src/users/dto/public-user.dto';

export const ApiUsersLinks = {
  getById200() {
    return applyDecorators(
      ApiExtraModels(PublicUserDto),
      ApiOkResponse({
        description: 'Користувач знайдений',
        type: PublicUserDto,
        links: {
          update: {
            operationId: 'users_update',
            description: 'Далі: оновити користувача (ADMIN)',
          },
          delete: {
            operationId: 'users_delete',
            description: 'Далі: видалити користувача (ADMIN)',
          },
          getByEmail: {
            operationId: 'users_getByEmail',
            description: 'Далі: знайти користувача за email (ADMIN/MODERATOR)',
          },
        },
      }),
    );
  },

  getByEmail200() {
    return applyDecorators(
      ApiExtraModels(PublicUserDto),
      ApiOkResponse({
        description: 'Користувач знайдений',
        type: PublicUserDto,
        links: {
          getById: {
            operationId: 'users_getById',
            description: 'Далі: отримати користувача за ID (ADMIN/MODERATOR)',
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
      }),
    );
  },

  update200() {
    return applyDecorators(
      ApiExtraModels(PublicUserDto),
      ApiOkResponse({
        description: 'Користувач оновлений',
        type: PublicUserDto,
        links: {
          getById: {
            operationId: 'users_getById',
            description: 'Далі: перевірити користувача за ID (ADMIN/MODERATOR)',
          },
          delete: {
            operationId: 'users_delete',
            description: 'Далі: видалити користувача (ADMIN)',
          },
        },
      }),
    );
  },

  delete200() {
    return applyDecorators(
      ApiExtraModels(PublicUserDto),
      ApiOkResponse({
        description: 'Користувач видалений',
        type: PublicUserDto,
        links: {
          getByEmail: {
            operationId: 'users_getByEmail',
            description:
              'Далі: перевірити, що користувача більше нема (ADMIN/MODERATOR)',
          },
        },
      }),
    );
  },
};
