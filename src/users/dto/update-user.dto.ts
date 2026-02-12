import {
  IsEmail,
  IsEnum,
  IsOptional,
  IsString,
  Validate,
} from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';
import { Role } from '@prisma/client';
import { PasswordPolicyValidator } from 'src/common/validators/password-policy.validator';

export class UpdateUserDto {
  @ApiPropertyOptional({ example: 'user@example.com', format: 'email' })
  @IsEmail()
  @IsOptional()
  email?: string;

  @ApiPropertyOptional({
    example: 'StrongPassword123',
    description:
      'Пароль згідно політики безпеки (довжина/вимоги задаються через ENV)',
  })
  @IsString()
  @IsOptional()
  @Validate(PasswordPolicyValidator)
  password?: string;

  @ApiPropertyOptional({ example: 'MODERATOR', enum: Role })
  @IsEnum(Role)
  @IsOptional()
  role?: Role;
}
