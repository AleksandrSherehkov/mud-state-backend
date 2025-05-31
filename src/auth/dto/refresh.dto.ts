import { ApiProperty } from '@nestjs/swagger';
import { IsJWT, IsNotEmpty, IsUUID } from 'class-validator';

export class RefreshDto {
  @ApiProperty({ example: 'clx123...', description: 'ID користувача' })
  @IsUUID()
  @IsNotEmpty()
  userId: string;

  @ApiProperty({ example: 'jwt.refresh.token', description: 'Refresh токен' })
  @IsJWT()
  @IsNotEmpty()
  refreshToken: string;
}
