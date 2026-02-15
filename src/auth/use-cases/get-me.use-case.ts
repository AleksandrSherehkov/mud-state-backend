import { Injectable, NotFoundException } from '@nestjs/common';
import { UsersService } from 'src/users/users.service';

@Injectable()
export class GetMeUseCase {
  constructor(private readonly users: UsersService) {}

  async execute(userId: string) {
    const user = await this.users.findById(userId);
    if (!user) throw new NotFoundException('Користувача не знайдено');
    return user;
  }
}
