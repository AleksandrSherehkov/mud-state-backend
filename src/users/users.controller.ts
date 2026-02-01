import {
  Body,
  Controller,
  Delete,
  Get,
  NotFoundException,
  Param,
  Patch,
  Query,
  UseGuards,
} from '@nestjs/common';
import { UsersService } from './users.service';
import {
  ApiTags,
  ApiOperation,
  ApiParam,
  ApiBearerAuth,
  ApiQuery,
} from '@nestjs/swagger';
import { PublicUserDto } from './dto/public-user.dto';
import {
  ApiMutationErrorResponses,
  ApiQueryErrorResponses,
} from 'src/common/swagger/api-exceptions';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { RolesGuard } from 'src/common/guards/roles.guard';
import { Roles } from 'src/common/decorators/roles.decorator';
import { Role } from '@prisma/client';
import { SkipThrottle } from '@nestjs/throttler';
import { UpdateUserDto } from './dto/update-user.dto';
import { GetUserByEmailQueryDto } from './dto/get-user-by-email.query';
import { USERS_SIDE_EFFECTS } from 'src/common/swagger/users.swagger';
import { ApiRolesAccess } from 'src/common/swagger/api-roles';
import { ApiUsersLinks } from 'src/common/swagger/users.links';

@ApiTags('users')
@Controller({
  path: 'users',
  version: '1',
})
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get('id/:id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @SkipThrottle()
  @Roles(Role.ADMIN, Role.MODERATOR)
  @ApiBearerAuth()
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
    includeTooManyRequests: false,
  })
  async getById(@Param('id') id: string) {
    const user = await this.usersService.findById(id);
    if (!user) throw new NotFoundException('Користувача не знайдено');
    return new PublicUserDto(user);
  }

  @Get('by-email')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @SkipThrottle()
  @Roles(Role.ADMIN, Role.MODERATOR)
  @ApiBearerAuth()
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
    includeTooManyRequests: false,
  })
  async getByEmail(@Query() query: GetUserByEmailQueryDto) {
    const user = await this.usersService.findByEmail(query.email);
    if (!user) throw new NotFoundException('Користувача не знайдено');
    return new PublicUserDto(user);
  }

  @Patch(':id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @SkipThrottle()
  @Roles(Role.ADMIN)
  @ApiBearerAuth()
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
  @ApiUsersLinks.update200()
  @ApiMutationErrorResponses({
    notFoundMessage: 'Користувача не знайдено',
    conflictDescription: 'Email вже використовується',
    conflictMessageExample: 'Email вже використовується',
    includeTooManyRequests: false,
  })
  async update(@Param('id') id: string, @Body() dto: UpdateUserDto) {
    const user = await this.usersService.updateUser(id, dto);
    return new PublicUserDto(user);
  }

  @Delete(':id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @SkipThrottle()
  @Roles(Role.ADMIN)
  @ApiBearerAuth()
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
    includeTooManyRequests: false,
  })
  async delete(@Param('id') id: string) {
    const user = await this.usersService.deleteUser(id);
    return new PublicUserDto(user);
  }
}
