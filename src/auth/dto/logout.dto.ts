import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsUUID } from 'class-validator';

export class LogoutDto {
  @ApiProperty({ example: 'clx123...', description: 'ID користувача' })
  @IsUUID()
  @IsNotEmpty()
  userId: string;
}
