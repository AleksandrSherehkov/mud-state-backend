import { AppLogger } from './logger.service';

type WinstonLike = {
  info: jest.Mock<void, [message: string, meta?: unknown]>;
  error: jest.Mock<void, [message: string, meta?: unknown]>;
  warn: jest.Mock<void, [message: string, meta?: unknown]>;
  debug: jest.Mock<void, [message: string, meta?: unknown]>;
  verbose: jest.Mock<void, [message: string, meta?: unknown]>;
  silly: jest.Mock<void, [message: string, meta?: unknown]>;
};

type LogFn = jest.Mock<void, [message: string, meta?: unknown]>;

describe('AppLogger', () => {
  let winstonLogger: WinstonLike;
  let logger: AppLogger;

  beforeEach(() => {
    const mk = (): LogFn => jest.fn<void, [string, unknown?]>();

    winstonLogger = {
      info: mk(),
      error: mk(),
      warn: mk(),
      debug: mk(),
      verbose: mk(),
      silly: mk(),
    };

    logger = new AppLogger(winstonLogger as unknown as any);
  });

  it('setContext stores context', () => {
    logger.setContext('MyContext');
    logger.log('msg');

    expect(winstonLogger.info).toHaveBeenCalledWith('msg', {
      context: 'MyContext',
    });
  });

  it('log uses explicit context over stored context', () => {
    logger.setContext('Ctx');
    logger.log('msg', 'Other');

    expect(winstonLogger.info).toHaveBeenCalledWith('msg', {
      context: 'Other',
    });
  });

  it('log passes undefined context when neither stored nor explicit is provided', () => {
    logger.log('msg');

    expect(winstonLogger.info).toHaveBeenCalledWith('msg', {
      context: undefined,
    });
  });

  it('error logs message with trace and context (stored)', () => {
    logger.setContext('ErrCtx');
    logger.error('err', 'trace-stack');

    expect(winstonLogger.error).toHaveBeenCalledWith('err', {
      context: 'ErrCtx',
      trace: 'trace-stack',
    });
  });

  it('error uses explicit context over stored context', () => {
    logger.setContext('Ctx');
    logger.error('err2', 'trace', 'Ctx2');

    expect(winstonLogger.error).toHaveBeenCalledWith('err2', {
      context: 'Ctx2',
      trace: 'trace',
    });
  });

  it.each([
    ['warn', 'warnMsg', 'warn'],
    ['debug', 'debugMsg', 'debug'],
    ['verbose', 'verbMsg', 'verbose'],
    ['silly', 'sillyMsg', 'silly'],
  ] as const)(
    '%s logs via winston.%s with stored context',
    (method, msg, winstonMethod) => {
      logger.setContext('Ctx3');

      (logger[method] as (m: string) => void)(msg);

      expect(winstonLogger[winstonMethod]).toHaveBeenCalledWith(msg, {
        context: 'Ctx3',
      });
    },
  );

  it('warn/debug/verbose/silly use explicit context over stored context', () => {
    logger.setContext('Ctx');
    logger.warn('w', 'C2');
    logger.debug('d', 'C2');
    logger.verbose('v', 'C2');
    logger.silly('s', 'C2');

    expect(winstonLogger.warn).toHaveBeenCalledWith('w', { context: 'C2' });
    expect(winstonLogger.debug).toHaveBeenCalledWith('d', { context: 'C2' });
    expect(winstonLogger.verbose).toHaveBeenCalledWith('v', { context: 'C2' });
    expect(winstonLogger.silly).toHaveBeenCalledWith('s', { context: 'C2' });
  });
});
