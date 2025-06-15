import {
  BadRequestException,
  Body,
  ConflictException,
  Controller,
  Get,
  HttpCode,
  UnauthorizedException,
  NotFoundException,
  Param,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { Request } from 'express';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshDto } from './dto/refresh.dto';

import { AuthService } from './auth.service';

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
import { SkipThrottle } from '@nestjs/throttler';

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
import { Roles } from './decorators/roles.decorator';
import { RolesGuard } from './guards/roles.guard';
import { LogoutResponseDto } from './dto/logout-response.dto';
import { RegisterResponseDto } from './dto/register-response.dto';
import { UserFromJwt } from './types/user-from-jwt';
import { Role } from '@prisma/client';
import { SessionService } from './session.service';
import { RefreshTokenService } from './refresh-token.service';
import { UsersService } from 'src/users/users.service';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private prisma: PrismaService,
    private sessionService: SessionService,
    private refreshTokenService: RefreshTokenService,
    private usersService: UsersService,
  ) {}

  @Post('register')
  @HttpCode(201)
  @ApiOperation({
    summary: 'Реєстрація нового користувача',
    description: `Створює нового користувача, одразу авторизує його і повертає токени доступу (accessToken, refreshToken), а також створює відповідну сесію і refreshToken у базі даних.`,
  })
  @ApiBody({ type: RegisterDto })
  @ApiCreatedResponse({
    description: 'Користувач успішно створений',
    type: RegisterResponseDto,
  })
  @ApiMutationErrorResponses()
  async register(
    @Body() dto: RegisterDto,
    @Req() req: Request,
  ): Promise<RegisterResponseDto> {
    const { ip, userAgent } = extractRequestInfo(req);

    const result = await this.authService.register(dto, ip, userAgent);
    return new RegisterResponseDto(result);
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
  @SkipThrottle()
  @ApiBearerAuth()
  @HttpCode(200)
  @ApiOperation({
    summary: 'Вихід користувача (очищення refresh токена та сесій)',
  })
  @ApiOkResponse({
    description: 'Користувач вийшов із системи',
    type: LogoutResponseDto,
  })
  @ApiMutationErrorResponses()
  async logout(@CurrentUser('userId') userId: string) {
    const result = await this.authService.logout(userId);

    if (!result.loggedOut) {
      throw new BadRequestException('Користувач вже вийшов із системи');
    }

    return result;
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  @SkipThrottle()
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Отримати інформацію про себе' })
  @ApiOkResponse({
    description: 'Повертає ID, email та роль користувача з бази',
    type: MeResponseDto,
  })
  @ApiQueryErrorResponses('Користувача не знайдено')
  async getMe(@CurrentUser('userId') userId: string): Promise<MeResponseDto> {
    const user = await this.usersService.findById(userId);
    if (!user) {
      throw new NotFoundException('Користувача не знайдено');
    }
    return new MeResponseDto(user);
  }

  @Get(':userId/sessions')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @SkipThrottle()
  @Roles(Role.ADMIN, Role.MODERATOR)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Список активних сесій користувача' })
  @ApiOkResponse({
    description: 'Список сесій з IP та User-Agent',
    type: [RefreshTokenSessionDto],
  })
  @ApiQueryErrorResponses('Сесії користувача не знайдено')
  async getSessions(
    @Param('userId') userId: string,
  ): Promise<RefreshTokenSessionDto[]> {
    const tokens = await this.refreshTokenService.getActiveTokens(userId);
    return tokens.map((token) => ({
      jti: token.jti,
      ip: token.ip ?? '',
      userAgent: token.userAgent ?? '',
      createdAt: token.createdAt.toISOString(),
    }));
  }

  @Get('sessions/active')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @SkipThrottle()
  @Roles(Role.ADMIN, Role.MODERATOR)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Список активних сесій поточного користувача' })
  @ApiOkResponse({
    description: 'Список активних сесій з IP, User-Agent і часом старту',
    type: [ActiveSessionDto],
  })
  @ApiQueryErrorResponses('Активні сесії не знайдено')
  async getActiveSessions(
    @CurrentUser('userId') userId: string,
  ): Promise<ActiveSessionDto[]> {
    const sessions = await this.sessionService.getActiveUserSessions(userId);
    return sessions.map((session) => ({
      id: session.id,
      ip: session.ip ?? '',
      userAgent: session.userAgent ?? '',
      startedAt: session.startedAt.toISOString(),
    }));
  }

  @Post('sessions/terminate-others')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @SkipThrottle()
  @Roles(Role.ADMIN, Role.MODERATOR)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Завершити всі інші сесії, крім поточної' })
  @ApiOkResponse({
    description: 'Інші сесії завершено',
    type: TerminateCountResponseDto,
  })
  @ApiMutationErrorResponses()
  async terminateOtherSessions(@CurrentUser() user: UserFromJwt | undefined) {
    if (!user) {
      throw new UnauthorizedException();
    }

    const result = await this.sessionService.terminateOtherSessions(
      user.userId,
      user.sid,
    );
    if (result.count === 0) {
      throw new ConflictException('Немає інших активних сесій');
    }
    return { terminatedCount: result.count };
  }

  @Get('sessions/me')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @SkipThrottle()
  @Roles(Role.ADMIN, Role.MODERATOR)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Список всіх сесій користувача' })
  @ApiOkResponse({
    description: 'Усі сесії поточного користувача',
    type: [FullSessionDto],
  })
  @ApiQueryErrorResponses('Сесії користувача не знайдено')
  async getMySessions(
    @CurrentUser('userId') userId: string,
  ): Promise<FullSessionDto[]> {
    const sessions = await this.sessionService.getAllUserSessions(userId);
    return sessions.map((session) => ({
      id: session.id,
      ip: session.ip ?? '',
      userAgent: session.userAgent ?? '',
      isActive: session.isActive,
      startedAt: session.startedAt.toISOString(),
      endedAt: session.endedAt ? session.endedAt.toISOString() : null,
    }));
  }

  @Post('sessions/terminate')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @SkipThrottle()
  @Roles(Role.ADMIN, Role.MODERATOR)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Завершити конкретну сесію за IP та User-Agent' })
  @ApiOkResponse({
    description: 'Сесію завершено',
    type: TerminateResultDto,
  })
  @ApiMutationErrorResponses()
  async terminateSpecificSession(
    @CurrentUser('userId') userId: string,
    @Body() dto: TerminateSessionDto,
  ) {
    const { ip, userAgent } = dto;

    const result = await this.sessionService.terminateSpecificSession(
      userId,
      ip,
      userAgent,
    );
    return { terminated: result.count > 0 };
  }
}
