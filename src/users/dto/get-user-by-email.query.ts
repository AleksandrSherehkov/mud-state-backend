import { ApiProperty } from '@nestjs/swagger';
import { Transform, type TransformFnParams } from 'class-transformer';
import { IsEmail, IsNotEmpty } from 'class-validator';

function trimIfString(value: unknown): unknown {
  return typeof value === 'string' ? value.trim() : value;
}

export class GetUserByEmailQueryDto {
  @ApiProperty({ example: 'user@example.com', format: 'email' })
  @Transform(({ value }: TransformFnParams) => trimIfString(value as unknown))
  @IsEmail()
  @IsNotEmpty()
  email: string;
}
