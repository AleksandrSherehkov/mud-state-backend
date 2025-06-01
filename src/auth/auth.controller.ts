import {
  Body,
  Controller,
  Get,
  HttpCode,
  Param,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { Request } from 'express';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshDto } from './dto/refresh.dto';
import { LogoutDto } from './dto/logout.dto';
import { AuthService } from './auth.service';
import { PublicUserDto } from '../users/dto/public-user.dto';
import {
  ApiBearerAuth,
  ApiBody,
  ApiCreatedResponse,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';
import {
  ApiMutationErrorResponses,
  ApiQueryErrorResponses,
} from 'src/common/swagger/api-exceptions';
import { Tokens } from './types/jwt.types';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { CurrentUser } from './decorators/current-user.decorator';
import { UserFromJwt } from './types/user-from-jwt';
import { TokenResponseDto } from './dto/token-response.dto';
import { MeResponseDto } from './dto/me-response.dto';
import { PrismaService } from '../prisma/prisma.service';
import { extractRequestInfo } from 'src/common/helpers/request-info';
import { TerminateSessionDto } from './dto/terminate-session.dto';
import { ActiveSessionDto } from './dto/active-session.dto';
import { RefreshTokenSessionDto } from './dto/refresh-token-session.dto';
import { TerminateCountResponseDto } from './dto/terminate-count-response.dto';
import { TerminateResultDto } from './dto/terminate-result.dto';
import { FullSessionDto } from './dto/full-session.dto';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private prisma: PrismaService,
  ) {}

  @Post('register')
  @HttpCode(201)
  @ApiOperation({ summary: 'Реєстрація нового користувача' })
  @ApiBody({ type: RegisterDto })
  @ApiCreatedResponse({
    description: 'Користувач успішно створений',
    type: PublicUserDto,
  })
  @ApiMutationErrorResponses()
  async register(
    @Body() dto: RegisterDto,
    @Req() req: Request,
  ): Promise<PublicUserDto> {
    const { ip, userAgent } = extractRequestInfo(req);

    const user = await this.authService.register(dto, ip, userAgent);
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
  async login(@Body() dto: LoginDto, @Req() req: Request): Promise<Tokens> {
    const { ip, userAgent } = extractRequestInfo(req);
    return this.authService.login(dto, ip, userAgent);
  }

  @Post('refresh')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @HttpCode(200)
  @ApiOperation({ summary: 'Оновлення токенів' })
  @ApiBody({ type: RefreshDto })
  @ApiOkResponse({ type: TokenResponseDto })
  @ApiMutationErrorResponses()
  async refresh(@Body() dto: RefreshDto, @Req() req: Request): Promise<Tokens> {
    const { ip, userAgent } = extractRequestInfo(req);
    return this.authService.refresh(
      dto.userId,
      dto.refreshToken,
      ip,
      userAgent,
    );
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
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
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Отримати інформацію про себе' })
  @ApiOkResponse({
    description: 'Повертає ID та email користувача з access токена',
    type: MeResponseDto,
  })
  @ApiQueryErrorResponses('Користувача не знайдено')
  getMe(@CurrentUser() user: UserFromJwt): UserFromJwt {
    return user;
  }

  @Get(':userId/sessions')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Список активних сесій користувача' })
  @ApiOkResponse({
    description: 'Список сесій з IP та User-Agent',
    type: [RefreshTokenSessionDto],
  })
  @ApiQueryErrorResponses('Сесії користувача не знайдено')
  getSessions(@Param('userId') userId: string) {
    return this.prisma.refreshToken.findMany({
      where: { userId, revoked: false },
      select: {
        jti: true,
        ip: true,
        userAgent: true,
        createdAt: true,
      },
    });
  }

  @Get('sessions/active')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Список активних сесій поточного користувача' })
  @ApiOkResponse({
    description: 'Список активних сесій з IP, User-Agent і часом старту',
    type: [ActiveSessionDto],
  })
  @ApiQueryErrorResponses('Активні сесії не знайдено')
  getActiveSessions(@CurrentUser('userId') userId: string) {
    return this.prisma.session.findMany({
      where: { userId, isActive: true },
      select: {
        id: true,
        ip: true,
        userAgent: true,
        startedAt: true,
      },
    });
  }

  @Post('sessions/terminate-others')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Завершити всі інші сесії, крім поточної' })
  @ApiOkResponse({
    description: 'Інші сесії завершено',
    type: TerminateCountResponseDto,
  })
  @ApiMutationErrorResponses()
  async terminateOtherSessions(
    @CurrentUser('userId') userId: string,
    @Req() req: Request,
  ) {
    const { ip, userAgent } = extractRequestInfo(req);

    const session = await this.prisma.session.findFirst({
      where: {
        userId,
        ip,
        userAgent,
        isActive: true,
      },
      orderBy: { startedAt: 'desc' },
    });

    const result = await this.prisma.session.updateMany({
      where: {
        userId,
        isActive: true,
        NOT: {
          id: session?.id,
        },
      },
      data: {
        isActive: false,
        endedAt: new Date(),
      },
    });

    return { terminatedCount: result.count };
  }

  @Get('sessions/me')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Список всіх сесій користувача' })
  @ApiOkResponse({
    description: 'Усі сесії поточного користувача',
    type: [FullSessionDto],
  })
  @ApiQueryErrorResponses('Сесії користувача не знайдено')
  getMySessions(@CurrentUser('userId') userId: string) {
    return this.prisma.session.findMany({
      where: { userId },
      orderBy: { startedAt: 'desc' },
      select: {
        id: true,
        ip: true,
        userAgent: true,
        isActive: true,
        startedAt: true,
        endedAt: true,
      },
    });
  }

  @Post('sessions/terminate')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Завершити конкретну сесію за IP та User-Agent' })
  @ApiOkResponse({
    description: 'Сесію завершено',
    type: TerminateResultDto,
  })
  @ApiMutationErrorResponses()
  async terminateSpecificSession(
    @CurrentUser('userId') userId: string,
    @Req() req: Request,
    @Body() dto: TerminateSessionDto,
  ) {
    const userAgent = req.headers['user-agent'] || '';
    const ip = dto.ip;

    const session = await this.prisma.session.findFirst({
      where: {
        userId,
        ip,
        userAgent,
        isActive: true,
      },
    });

    if (!session) {
      return { terminated: false };
    }

    await this.prisma.session.update({
      where: { id: session.id },
      data: {
        isActive: false,
        endedAt: new Date(),
      },
    });

    return { terminated: true };
  }
}
