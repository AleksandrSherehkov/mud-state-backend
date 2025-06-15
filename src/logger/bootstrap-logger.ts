import * as winston from 'winston';

type LogInfo = winston.Logform.TransformableInfo & { context?: string };

const consoleFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp(),
  winston.format.printf((info: LogInfo) => {
    const timestamp = info.timestamp?.toString() ?? '';
    const level = info.level?.toString() ?? '';
    const ctx = String(info.context ?? 'App');
    const message: string = (() => {
      if (typeof info.message === 'undefined' || info.message === null)
        return '';
      if (typeof info.message === 'object') return JSON.stringify(info.message);
      return String(info.message as string | number | boolean);
    })();

    return `[${timestamp}] ${level} [${ctx}] ${message}`.trim();
  }),
);

export const bootstrapLogger = winston.createLogger({
  level: 'debug',
  transports: [
    new winston.transports.Console({
      format: consoleFormat,
    }),
  ],
});
