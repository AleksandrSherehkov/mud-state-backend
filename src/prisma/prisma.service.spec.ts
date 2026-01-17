import { Test, TestingModule } from '@nestjs/testing';
import { PrismaService } from './prisma.service';
import { AppLogger } from 'src/logger/logger.service';

describe('PrismaService', () => {
  let service: PrismaService;

  const loggerMock: jest.Mocked<
    Pick<AppLogger, 'setContext' | 'log' | 'error'>
  > = {
    setContext: jest.fn(),
    log: jest.fn(),
    error: jest.fn(),
  };

  let connectSpy: jest.SpyInstance<Promise<void>, []>;
  let disconnectSpy: jest.SpyInstance<Promise<void>, []>;

  beforeEach(async () => {
    jest.clearAllMocks();

    process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/testdb';

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PrismaService,
        {
          provide: AppLogger,
          useValue: loggerMock,
        },
      ],
    }).compile();

    service = module.get(PrismaService);

    connectSpy = jest.spyOn(service, '$connect').mockResolvedValue(undefined);
    disconnectSpy = jest
      .spyOn(service, '$disconnect')
      .mockResolvedValue(undefined);
  });

  it('should be defined and set logger context', () => {
    expect(service).toBeDefined();
    expect(loggerMock.setContext).toHaveBeenCalledWith(PrismaService.name);
  });

  it('onModuleInit should log start/success and connect', async () => {
    await service.onModuleInit();

    expect(loggerMock.log).toHaveBeenCalledWith(
      'Connecting to database',
      PrismaService.name,
      { event: 'prisma.connect.start' },
    );

    expect(connectSpy).toHaveBeenCalledTimes(1);

    expect(loggerMock.log).toHaveBeenCalledWith(
      'Database connected',
      PrismaService.name,
      { event: 'prisma.connect.success' },
    );
  });

  it('onModuleInit should log error and throw when connect fails', async () => {
    connectSpy.mockRejectedValueOnce(new Error('boom'));

    await expect(service.onModuleInit()).rejects.toThrow('boom');

    expect(loggerMock.error).toHaveBeenCalled();
  });

  it('onModuleDestroy should log start/success and disconnect', async () => {
    await service.onModuleDestroy();

    expect(loggerMock.log).toHaveBeenCalledWith(
      'Disconnecting from database',
      PrismaService.name,
      { event: 'prisma.disconnect.start' },
    );

    expect(disconnectSpy).toHaveBeenCalledTimes(1);

    expect(loggerMock.log).toHaveBeenCalledWith(
      'Database disconnected',
      PrismaService.name,
      { event: 'prisma.disconnect.success' },
    );
  });

  it('onModuleDestroy should log error and throw when disconnect fails', async () => {
    disconnectSpy.mockRejectedValueOnce(new Error('bye'));

    await expect(service.onModuleDestroy()).rejects.toThrow('bye');

    expect(loggerMock.error).toHaveBeenCalled();
  });
});
