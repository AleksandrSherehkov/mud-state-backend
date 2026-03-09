import { Injectable } from '@nestjs/common';

import { SessionsService } from './sessions.service';
import { TerminateSessionDto } from './dto/terminate-session.dto';
import { FullSessionDto } from './dto/full-session.dto';
import { TerminateCountResponseDto } from './dto/terminate-count-response.dto';
import { TerminateResultDto } from './dto/terminate-result.dto';
import { toFullSessionDto } from './session-presenter.util';

@Injectable()
export class SessionsHttpService {
  constructor(private readonly sessions: SessionsService) {}

  private async listUserSessions(userId: string): Promise<FullSessionDto[]> {
    const sessions = await this.sessions.getAllUserSessions(userId);
    return sessions.map((s) => toFullSessionDto(s));
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
      params.sid,
    );

    return new TerminateCountResponseDto({
      terminatedCount: res.count,
    });
  }

  async terminateSpecific(
    userId: string,
    dto: TerminateSessionDto,
  ): Promise<TerminateResultDto> {
    const res = await this.sessions.terminateById({
      sid: dto.sessionId,
      userId,
      reason: 'api_terminate_specific',
    });

    return new TerminateResultDto({
      terminated: res.count > 0,
    });
  }

  getUserSessions(userId: string): Promise<FullSessionDto[]> {
    return this.listUserSessions(userId);
  }
}
