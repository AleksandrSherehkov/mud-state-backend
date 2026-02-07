import { Injectable } from '@nestjs/common';
import { Session as PrismaSession } from '@prisma/client';

import { SessionService } from './session.service';

import { TerminateSessionDto } from './dto/terminate-session.dto';
import { FullSessionDto } from './dto/full-session.dto';
import { TerminateCountResponseDto } from './dto/terminate-count-response.dto';
import { TerminateResultDto } from './dto/terminate-result.dto';

@Injectable()
export class SessionsHttpService {
  constructor(private readonly sessions: SessionService) {}

  private toFullSessionDto(s: PrismaSession): FullSessionDto {
    return {
      id: s.id,
      ip: s.ip ?? '',
      userAgent: s.userAgent ?? '',
      isActive: s.isActive,
      startedAt: s.startedAt.toISOString(),
      endedAt: s.endedAt?.toISOString() ?? null,
    };
  }

  private async listUserSessions(userId: string): Promise<FullSessionDto[]> {
    const sessions = await this.sessions.getAllUserSessions(userId);
    return sessions.map(s => this.toFullSessionDto(s));
  }

  mySessions(userId: string): Promise<FullSessionDto[]> {
    return this.listUserSessions(userId);
  }

  async terminateOthers(params: {
    userId: string;
    sid: string;
  }): Promise<TerminateCountResponseDto> {
    const res = await this.sessions.terminateOtherSessions(
      params.userId,
      params.sid
    );
    return { terminatedCount: res.count };
  }

  async terminateSpecific(
    userId: string,
    dto: TerminateSessionDto
  ): Promise<TerminateResultDto> {
    const res = await this.sessions.terminateSpecificSession(
      userId,
      dto.ip,
      dto.userAgent
    );
    return { terminated: res.count > 0 };
  }

  getUserSessions(userId: string): Promise<FullSessionDto[]> {
    return this.listUserSessions(userId);
  }
}
