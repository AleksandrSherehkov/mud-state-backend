import { ApiProperty } from '@nestjs/swagger';
import { Role } from '@prisma/client';

import { PublicUserDto } from 'src/users/dto/public-user.dto';

export class RegisterResponseDto extends PublicUserDto {
  @ApiProperty({ example: 'access.jwt.token' })
  accessToken: string;

  @ApiProperty({ example: 'refresh.jwt.token' })
  refreshToken: string;

  @ApiProperty({ example: 'uuid', description: 'JWT ID' })
  jti: string;

  constructor(data: {
    id: string;
    email: string;
    role: Role;
    createdAt: Date;
    accessToken: string;
    refreshToken: string;
    jti: string;
  }) {
    super({
      id: data.id,
      email: data.email,
      role: data.role,
      createdAt: data.createdAt,
    });

    this.accessToken = data.accessToken;
    this.refreshToken = data.refreshToken;
    this.jti = data.jti;
  }
}
