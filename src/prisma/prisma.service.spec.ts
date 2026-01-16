import { Test, TestingModule } from '@nestjs/testing';
import { PrismaService } from './prisma.service';
import { AppLogger } from 'src/logger/logger.service';

describe('PrismaService', () => {
  let service: PrismaService;

  const loggerMock: jest.Mocked<Pick<AppLogger, 'setContext' | 'log'>> = {
    setContext: jest.fn(),
    log: jest.fn(),
  };

  let connectSpy: jest.SpyInstance<Promise<void>, []>;
  let disconnectSpy: jest.SpyInstance<Promise<void>, []>;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [PrismaService, { provide: AppLogger, useValue: loggerMock }],
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

  it('onModuleInit should log and connect', async () => {
    await service.onModuleInit();

    expect(loggerMock.log).toHaveBeenCalledWith(
      '[PrismaService] Connecting to database...',
    );
    expect(connectSpy).toHaveBeenCalledTimes(1);
  });

  it('onModuleDestroy should log and disconnect', async () => {
    await service.onModuleDestroy();

    expect(loggerMock.log).toHaveBeenCalledWith(
      '[PrismaService] Disconnecting from database...',
    );
    expect(disconnectSpy).toHaveBeenCalledTimes(1);
  });
});
