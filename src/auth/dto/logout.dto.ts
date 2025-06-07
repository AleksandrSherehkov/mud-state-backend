import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class LogoutDto {
  @ApiProperty({ example: 'clx123...', description: 'ID користувача' })
  @IsString()
  @IsNotEmpty()
  userId: string;
}
