import { ApiProperty } from '@nestjs/swagger';

export class TerminateResultDto {
  @ApiProperty({ example: true })
  terminated: boolean;

  constructor(data: { terminated: boolean }) {
    this.terminated = data.terminated;
  }
}
