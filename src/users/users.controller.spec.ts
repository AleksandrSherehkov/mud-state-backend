import { NotFoundException } from '@nestjs/common';
import { Role, type User } from '@prisma/client';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { PublicUserDto } from './dto/public-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { GetUserByEmailQueryDto } from './dto/get-user-by-email.query';

describe('UsersController', () => {
  let controller: UsersController;

  let usersService: jest.Mocked<
    Pick<UsersService, 'findById' | 'findByEmail' | 'updateUser' | 'deleteUser'>
  >;

  const makeUser = (overrides: Partial<User> = {}): User => ({
    id: 'u1',
    email: 'user@example.com',
    password: 'hash',
    role: Role.USER,
    createdAt: new Date('2025-01-01T00:00:00Z'),
    ...overrides,
  });

  beforeEach(() => {
    usersService = {
      findById: jest.fn(),
      findByEmail: jest.fn(),
      updateUser: jest.fn(),
      deleteUser: jest.fn(),
    };

    controller = new UsersController(usersService as unknown as UsersService);
  });

  describe('getById', () => {
    it('returns PublicUserDto when the user exists', async () => {
      const user = makeUser({ id: 'u1' });
      usersService.findById.mockResolvedValue(user);

      const result = await controller.getById('u1');

      expect(usersService.findById).toHaveBeenCalledWith('u1');
      expect(result).toEqual(new PublicUserDto(user));
    });

    it('throws NotFoundException when the user does not exist', async () => {
      usersService.findById.mockResolvedValue(null);

      await expect(controller.getById('missing')).rejects.toThrow(
        NotFoundException,
      );
      expect(usersService.findById).toHaveBeenCalledWith('missing');
    });
  });

  describe('getByEmail (GET /users/by-email?email=...)', () => {
    it('returns PublicUserDto when the user exists', async () => {
      const user = makeUser({ email: 'another@example.com', role: Role.ADMIN });
      usersService.findByEmail.mockResolvedValue(user);

      const query: GetUserByEmailQueryDto = { email: 'another@example.com' };
      const result = await controller.getByEmail(query);

      expect(usersService.findByEmail).toHaveBeenCalledWith(
        'another@example.com',
      );
      expect(result).toEqual(new PublicUserDto(user));
    });

    it('passes email as-is to service (normalization is done in service)', async () => {
      const user = makeUser({ email: 'target@e2e.local' });
      usersService.findByEmail.mockResolvedValue(user);

      const raw = '  TARGET@e2e.local  ';
      const query: GetUserByEmailQueryDto = { email: raw };
      const result = await controller.getByEmail(query);

      expect(usersService.findByEmail).toHaveBeenCalledWith(raw);
      expect(result).toEqual(new PublicUserDto(user));
    });

    it('throws NotFoundException when the user does not exist', async () => {
      usersService.findByEmail.mockResolvedValue(null);

      const query: GetUserByEmailQueryDto = { email: 'missing@example.com' };

      await expect(controller.getByEmail(query)).rejects.toThrow(
        NotFoundException,
      );

      expect(usersService.findByEmail).toHaveBeenCalledWith(
        'missing@example.com',
      );
    });
  });

  describe('update', () => {
    it('calls usersService.updateUser and returns PublicUserDto', async () => {
      const dto: UpdateUserDto = { email: 'updated@example.com' };
      const updated = makeUser({
        id: 'u3',
        email: 'updated@example.com',
        role: Role.MODERATOR,
      });

      usersService.updateUser.mockResolvedValue(updated);

      const result = await controller.update('u3', dto);

      expect(usersService.updateUser).toHaveBeenCalledWith('u3', dto);
      expect(result).toEqual(new PublicUserDto(updated));
    });

    it('propagates NotFoundException from service', async () => {
      const dto: UpdateUserDto = { email: 'updated@example.com' };
      usersService.updateUser.mockRejectedValue(
        new NotFoundException('Користувача не знайдено'),
      );

      await expect(controller.update('missing', dto)).rejects.toThrow(
        NotFoundException,
      );
      expect(usersService.updateUser).toHaveBeenCalledWith('missing', dto);
    });
  });

  describe('delete', () => {
    it('calls usersService.deleteUser and returns PublicUserDto', async () => {
      const deleted = makeUser({ id: 'u4', email: 'deleted@example.com' });
      usersService.deleteUser.mockResolvedValue(deleted);

      const result = await controller.delete('u4');

      expect(usersService.deleteUser).toHaveBeenCalledWith('u4');
      expect(result).toEqual(new PublicUserDto(deleted));
    });

    it('propagates NotFoundException from service', async () => {
      usersService.deleteUser.mockRejectedValue(
        new NotFoundException('Користувача не знайдено'),
      );

      await expect(controller.delete('missing')).rejects.toThrow(
        NotFoundException,
      );
      expect(usersService.deleteUser).toHaveBeenCalledWith('missing');
    });
  });
});
