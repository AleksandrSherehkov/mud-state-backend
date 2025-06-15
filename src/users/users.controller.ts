import {
  Body,
  Controller,
  Delete,
  Get,
  NotFoundException,
  Param,
  Patch,
  UseGuards,
} from '@nestjs/common';
import { UsersService } from './users.service';
import {
  ApiTags,
  ApiOperation,
  ApiParam,
  ApiOkResponse,
  ApiBearerAuth,
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

@ApiTags('users')
@Controller('users')
export class UsersController {
  constructor(private usersService: UsersService) {}

  @Get('id/:id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @SkipThrottle()
  @Roles(Role.ADMIN, Role.MODERATOR)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Отримати користувача за ID' })
  @ApiParam({
    name: 'id',
    description: 'UUID користувача',
    example: 'clx1a2b3c0000n1m2o3p4q5r',
  })
  @ApiOkResponse({ description: 'Знайдений користувач', type: PublicUserDto })
  @ApiQueryErrorResponses('Користувача не знайдено')
  async getById(@Param('id') id: string) {
    const user = await this.usersService.findById(id);
    if (!user) throw new NotFoundException('Користувача не знайдено');
    return new PublicUserDto(user); // ✅
  }

  @Get('email/:email')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @SkipThrottle()
  @Roles(Role.ADMIN, Role.MODERATOR)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Пошук користувача за email' })
  @ApiParam({
    name: 'email',
    description: 'Email користувача',
    example: 'user@example.com',
  })
  @ApiOkResponse({ description: 'Знайдений користувач', type: PublicUserDto })
  @ApiQueryErrorResponses('Користувача не знайдено')
  async getByEmail(@Param('email') email: string) {
    const user = await this.usersService.findByEmail(email);
    if (!user) throw new NotFoundException('Користувача не знайдено');
    return new PublicUserDto(user); // ✅
  }

  @Patch(':id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @SkipThrottle()
  @Roles(Role.ADMIN)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Оновити користувача' })
  @ApiParam({ name: 'id', description: 'ID користувача' })
  @ApiOkResponse({ description: 'Користувача оновлено', type: PublicUserDto })
  @ApiMutationErrorResponses()
  async update(@Param('id') id: string, @Body() dto: UpdateUserDto) {
    const user = await this.usersService.updateUser(id, dto);
    return new PublicUserDto(user);
  }

  @Delete(':id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @SkipThrottle()
  @Roles(Role.ADMIN)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Видалити користувача' })
  @ApiParam({ name: 'id', description: 'ID користувача' })
  @ApiOkResponse({ description: 'Користувача видалено', type: PublicUserDto })
  @ApiQueryErrorResponses('Користувача не знайдено')
  async delete(@Param('id') id: string) {
    const user = await this.usersService.deleteUser(id);
    return new PublicUserDto(user);
  }
}
