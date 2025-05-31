import { Controller, Get, NotFoundException, Param } from '@nestjs/common';
import { UsersService } from './users.service';
import {
  ApiTags,
  ApiOperation,
  ApiParam,
  ApiOkResponse,
} from '@nestjs/swagger';
import { PublicUserDto } from './dto/public-user.dto';
import { ApiQueryErrorResponses } from 'src/common/swagger/api-exceptions';

@ApiTags('users')
@Controller('users')
export class UsersController {
  constructor(private usersService: UsersService) {}

  @Get(':email')
  @ApiOperation({ summary: 'Пошук користувача за email' })
  @ApiParam({
    name: 'email',
    description: 'Email користувача',
    example: 'user@example.com',
  })
  @ApiOkResponse({ type: PublicUserDto })
  @ApiQueryErrorResponses('Користувача не знайдено')
  async getByEmail(@Param('email') email: string) {
    const user = await this.usersService.findByEmail(email);
    if (!user) throw new NotFoundException('Користувача не знайдено');
    return {
      id: user.id,
      email: user.email,
      createdAt: user.createdAt,
    };
  }
}
