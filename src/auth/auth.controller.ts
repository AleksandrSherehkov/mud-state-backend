import {
  Body,
  Controller,
  Get,
  HttpCode,
  Post,
  Request,
  UseGuards,
} from '@nestjs/common';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshDto } from './dto/refresh.dto';
import { LogoutDto } from './dto/logout.dto';
import { AuthService } from './auth.service';
import { PublicUserDto } from '../users/dto/public-user.dto';
import {
  ApiBody,
  ApiCreatedResponse,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';
import { ApiMutationErrorResponses } from 'src/common/swagger/api-exceptions';
import { Tokens } from './types/jwt.types';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { CurrentUser } from './decorators/current-user.decorator';
import { UserFromJwt } from './types/user-from-jwt';
import { TokenResponseDto } from './dto/token-response.dto';
import { MeResponseDto } from './dto/me-response.dto';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  @HttpCode(201)
  @ApiOperation({ summary: 'Реєстрація нового користувача' })
  @ApiBody({ type: RegisterDto })
  @ApiCreatedResponse({
    description: 'Користувач успішно створений',
    type: PublicUserDto,
  })
  @ApiMutationErrorResponses()
  async register(@Body() dto: RegisterDto): Promise<PublicUserDto> {
    const user = await this.authService.register(dto);
    return {
      id: user.id,
      email: user.email,
      createdAt: user.createdAt,
    };
  }

  @Post('login')
  @HttpCode(200)
  @ApiOperation({ summary: 'Вхід користувача' })
  @ApiBody({ type: LoginDto })
  @ApiOkResponse({
    description: 'Успішний логін',
    type: TokenResponseDto,
  })
  @ApiMutationErrorResponses()
  async login(@Body() dto: LoginDto): Promise<Tokens> {
    return this.authService.login(dto);
  }

  @Post('refresh')
  @HttpCode(200)
  @ApiOperation({ summary: 'Оновлення токенів' })
  @ApiBody({ type: RefreshDto })
  @ApiOkResponse({ type: TokenResponseDto })
  @ApiMutationErrorResponses()
  async refresh(@Body() dto: RefreshDto) {
    return this.authService.refresh(dto.userId, dto.refreshToken);
  }

  @Post('logout')
  @HttpCode(200)
  @ApiOperation({ summary: 'Вихід користувача (очищення refresh токена)' })
  @ApiBody({ type: LogoutDto })
  @ApiOkResponse({
    description: 'Користувач вийшов із системи',
  })
  @ApiMutationErrorResponses()
  async logout(@Body() dto: LogoutDto) {
    await this.authService.logout(dto.userId);
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Отримати інформацію про себе' })
  @ApiOkResponse({
    description: 'Повертає ID та email користувача з access токена',
    type: MeResponseDto,
  })
  getMe(@CurrentUser() user: UserFromJwt): UserFromJwt {
    return user;
  }
}
