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
  ApiOkResponse,
  ApiBearerAuth,
  ApiQuery,
} from '@nestjs/swagger';
import { PublicUserDto } from './dto/public-user.dto';
import {
  ApiMutationErrorResponses,
  ApiQueryErrorResponses,
} from 'src/common/swagger/api-exceptions';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { Role } from '@prisma/client';
import { SkipThrottle } from '@nestjs/throttler';
import { UpdateUserDto } from './dto/update-user.dto';
import { GetUserByEmailQueryDto } from './dto/get-user-by-email.query';

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
    summary: 'Отримати користувача за ID',
    description:
      'Повертає публічні дані користувача за його UUID. Доступ: ADMIN, MODERATOR.',
    operationId: 'users_getById',
  })
  @ApiParam({
    name: 'id',
    description: 'UUID користувача',
    schema: { type: 'string', format: 'uuid' },
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  @ApiOkResponse({ description: 'Знайдений користувач', type: PublicUserDto })
  @ApiQueryErrorResponses('Користувача не знайдено')
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
    summary: 'Пошук користувача за email',
    description:
      'Повертає публічні дані користувача за email. Email нормалізується (trim + lowercase). Доступ: ADMIN, MODERATOR.',
    operationId: 'users_getByEmail',
  })
  @ApiOkResponse({ description: 'Знайдений користувач', type: PublicUserDto })
  @ApiQueryErrorResponses('Користувача не знайдено')
  @ApiQuery({ name: 'email', required: true, example: 'user@example.com' })
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
    summary: 'Оновити користувача',
    description:
      'Оновлює email/password/role користувача. Доступ: тільки ADMIN. Пароль буде перехешовано. Email нормалізується (trim + lowercase).',
    operationId: 'users_update',
  })
  @ApiParam({
    name: 'id',
    description: 'UUID користувача',
    schema: { type: 'string', format: 'uuid' },
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  @ApiOkResponse({ description: 'Користувача оновлено', type: PublicUserDto })
  @ApiMutationErrorResponses({
    notFoundMessage: 'Користувача не знайдено',
    conflictDescription: 'Email вже використовується',
    conflictMessageExample: 'Email вже використовується',
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
    summary: 'Видалити користувача',
    description:
      'Видаляє користувача за UUID. Доступ: тільки ADMIN. Повертає публічні дані видаленого користувача.',
    operationId: 'users_delete',
  })
  @ApiParam({
    name: 'id',
    description: 'UUID користувача',
    schema: { type: 'string', format: 'uuid' },
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  @ApiOkResponse({ description: 'Користувача видалено', type: PublicUserDto })
  @ApiMutationErrorResponses({
    notFoundMessage: 'Користувача не знайдено',
    includeConflict: false,
  })
  async delete(@Param('id') id: string) {
    const user = await this.usersService.deleteUser(id);
    return new PublicUserDto(user);
  }
}
