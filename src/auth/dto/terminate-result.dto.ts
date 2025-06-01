import { ApiProperty } from '@nestjs/swagger';

export class TerminateResultDto {
  @ApiProperty({ example: true })
  terminated: boolean;
}
