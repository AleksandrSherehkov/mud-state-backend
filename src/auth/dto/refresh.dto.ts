import { ApiProperty } from '@nestjs/swagger';
import { IsJWT, IsNotEmpty, IsString } from 'class-validator';

export class RefreshDto {
  @ApiProperty({ example: 'clx123...', description: 'ID користувача' })
  @IsString()
  @IsNotEmpty()
  userId: string;

  @ApiProperty({ example: 'jwt.refresh.token', description: 'Refresh токен' })
  @IsJWT()
  @IsNotEmpty()
  refreshToken: string;
}
