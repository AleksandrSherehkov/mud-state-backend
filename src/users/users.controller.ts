import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  ParseUUIDPipe,
  Patch,
  Query,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiParam,
  ApiBearerAuth,
  ApiQuery,
  ApiBody,
} from '@nestjs/swagger';
import { Role } from '@prisma/client';
import { Throttle } from '@nestjs/throttler';

import { Roles } from 'src/common/decorators/roles.decorator';

import {
  ApiMutationErrorResponses,
  ApiQueryErrorResponses,
} from 'src/common/swagger/api-exceptions';
import { USERS_SIDE_EFFECTS } from 'src/common/swagger/users.swagger';
import { ApiRolesAccess } from 'src/common/swagger/api-roles';
import { ApiUsersLinks } from 'src/common/swagger/users.links';
import { THROTTLE_USERS } from 'src/common/throttle/throttle-env';

import { UpdateUserDto } from './dto/update-user.dto';
import { GetUserByEmailQueryDto } from './dto/get-user-by-email.query';
import { UsersHttpService } from './users-http.service';
import { RequireFreshAccess } from 'src/common/decorators/require-fresh-access.decorator';

@ApiTags('users')
@Controller({
  path: 'users',
  version: '1',
})
@ApiBearerAuth('access_bearer')
export class UsersController {
  constructor(private readonly usersHttp: UsersHttpService) {}

  @Get('id/:id')
  @Throttle({ default: THROTTLE_USERS.byId })
  @Roles(Role.ADMIN, Role.MODERATOR)
  @ApiOperation({
    summary: 'Отримати користувача за ID (ADMIN/MODERATOR)',
    operationId: 'users_getById',
  })
  @ApiRolesAccess([Role.ADMIN, Role.MODERATOR], {
    sideEffects: USERS_SIDE_EFFECTS.getById,
    notes: [
      'Потрібна авторизація (Bearer access token).',
      'Повертає лише публічні поля (без password).',
    ],
  })
  @ApiParam({
    name: 'id',
    description: 'UUID користувача',
    schema: { type: 'string', format: 'uuid' },
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  @ApiUsersLinks.getById200()
  @ApiQueryErrorResponses({
    notFoundMessage: 'Користувача не знайдено',
  })
  async getById(@Param('id', new ParseUUIDPipe({ version: '4' })) id: string) {
    return this.usersHttp.getById(id);
  }

  @Get('by-email')
  @Throttle({ default: THROTTLE_USERS.byEmail })
  @Roles(Role.ADMIN, Role.MODERATOR)
  @ApiOperation({
    summary: 'Пошук користувача за email (ADMIN/MODERATOR)',
    operationId: 'users_getByEmail',
  })
  @ApiRolesAccess([Role.ADMIN, Role.MODERATOR], {
    sideEffects: USERS_SIDE_EFFECTS.getByEmail,
    notes: [
      'Потрібна авторизація (Bearer access token).',
      'Email у query обов’язковий.',
    ],
  })
  @ApiQuery({
    name: 'email',
    required: true,
    description: 'Email користувача (trim у DTO, normalizeEmail у сервісі)',
    schema: { type: 'string', format: 'email' },
    examples: {
      example: { value: 'user@example.com' },
    },
  })
  @ApiUsersLinks.getByEmail200()
  @ApiQueryErrorResponses({
    notFoundMessage: 'Користувача не знайдено',
  })
  async getByEmail(@Query() query: GetUserByEmailQueryDto) {
    return this.usersHttp.getByEmail(query.email);
  }

  @Patch(':id')
  @RequireFreshAccess(300)
  @Throttle({ default: THROTTLE_USERS.update })
  @Roles(Role.ADMIN)
  @ApiOperation({
    summary: 'Оновити користувача (ADMIN)',
    operationId: 'users_update',
  })
  @ApiRolesAccess([Role.ADMIN], {
    sideEffects: USERS_SIDE_EFFECTS.update,
    notes: [
      'Потрібна авторизація (Bearer access token).',
      'Передавай лише поля, які треба змінити (partial update).',
    ],
  })
  @ApiParam({
    name: 'id',
    description: 'UUID користувача',
    schema: { type: 'string', format: 'uuid' },
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  @ApiBody({ type: UpdateUserDto })
  @ApiUsersLinks.update200()
  @ApiMutationErrorResponses({
    notFoundMessage: 'Користувача не знайдено',
    conflictDescription: 'Email вже використовується',
    conflictMessageExample: 'Email вже використовується',
  })
  async update(
    @Param('id', new ParseUUIDPipe({ version: '4' })) id: string,
    @Body() dto: UpdateUserDto,
  ) {
    return this.usersHttp.update(id, dto);
  }

  @Delete(':id')
  @RequireFreshAccess(300)
  @Throttle({ default: THROTTLE_USERS.delete })
  @Roles(Role.ADMIN)
  @ApiOperation({
    summary: 'Видалити користувача (ADMIN)',
    operationId: 'users_delete',
  })
  @ApiRolesAccess([Role.ADMIN], {
    sideEffects: USERS_SIDE_EFFECTS.delete,
    notes: [
      'Потрібна авторизація (Bearer access token).',
      'Операція незворотна.',
    ],
  })
  @ApiParam({
    name: 'id',
    description: 'UUID користувача',
    schema: { type: 'string', format: 'uuid' },
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  @ApiUsersLinks.delete200()
  @ApiMutationErrorResponses({
    notFoundMessage: 'Користувача не знайдено',
    includeConflict: false,
  })
  async delete(@Param('id', new ParseUUIDPipe({ version: '4' })) id: string) {
    return this.usersHttp.delete(id);
  }
}
