import {
  Controller,
  Get,
  NotFoundException,
  Param,
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
import { ApiQueryErrorResponses } from 'src/common/swagger/api-exceptions';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { Role } from 'src/common/enums/role.enum';

@ApiTags('users')
@Controller('users')
export class UsersController {
  constructor(private usersService: UsersService) {}

  @Get(':email')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Пошук користувача за email' })
  @ApiParam({
    name: 'email',
    description: 'Email користувача',
    example: 'user@example.com',
  })
  @ApiOkResponse({
    description: 'Знайдений користувач',
    type: PublicUserDto,
  })
  @ApiOkResponse({ type: PublicUserDto })
  @ApiQueryErrorResponses('Користувача не знайдено')
  async getByEmail(@Param('email') email: string) {
    const user = await this.usersService.findByEmail(email);
    if (!user) throw new NotFoundException('Користувача не знайдено');
    return {
      id: user.id,
      email: user.email,
      role: user.role,
      createdAt: user.createdAt,
    };
  }
}
