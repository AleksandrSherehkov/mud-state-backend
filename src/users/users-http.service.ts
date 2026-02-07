import { Injectable, NotFoundException } from '@nestjs/common';
import { UsersService } from './users.service';
import { PublicUserDto } from './dto/public-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';

@Injectable()
export class UsersHttpService {
  constructor(private readonly usersService: UsersService) {}

  async getById(id: string): Promise<PublicUserDto> {
    const user = await this.usersService.findById(id);
    if (!user) throw new NotFoundException('Користувача не знайдено');
    return new PublicUserDto(user);
  }

  async getByEmail(email: string): Promise<PublicUserDto> {
    const user = await this.usersService.findByEmail(email);
    if (!user) throw new NotFoundException('Користувача не знайдено');
    return new PublicUserDto(user);
  }

  async update(id: string, dto: UpdateUserDto): Promise<PublicUserDto> {
    const user = await this.usersService.updateUser(id, dto);
    return new PublicUserDto(user);
  }

  async delete(id: string): Promise<PublicUserDto> {
    const user = await this.usersService.deleteUser(id);
    return new PublicUserDto(user);
  }
}
