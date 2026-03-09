import { ApiProperty } from '@nestjs/swagger';

export class TerminateCountResponseDto {
  @ApiProperty({ example: 2 })
  terminatedCount: number;

  constructor(data: { terminatedCount: number }) {
    this.terminatedCount = data.terminatedCount;
  }
}
