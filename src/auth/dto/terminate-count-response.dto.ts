import { ApiProperty } from '@nestjs/swagger';

export class TerminateCountResponseDto {
  @ApiProperty({ example: 2 })
  terminatedCount: number;
}
