import * as winston from 'winston';
import 'winston-daily-rotate-file';
import { ConfigService } from '@nestjs/config';

type LogInfo = winston.Logform.TransformableInfo & { context?: string };

const consoleFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp(),
  winston.format.printf((info: LogInfo) => {
    const timestamp = info.timestamp?.toString() ?? '';
    const level = info.level?.toString() ?? '';
    const message: string = (() => {
      if (typeof info.message === 'undefined' || info.message === null)
        return '';
      if (typeof info.message === 'object') return JSON.stringify(info.message);
      return String(info.message as string | number | boolean);
    })();
    const ctx = String(info.context ?? 'App');

    return `[${timestamp}] ${level} [${ctx}] ${message}`.trim();
  }),
);

const fileFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.json(),
);

export const createWinstonTransports = (
  config: ConfigService,
): winston.transport[] => {
  const consoleTransport = new winston.transports.Console({
    format: consoleFormat,
  });

  const fileTransport = new winston.transports.DailyRotateFile({
    dirname: config.get('LOG_DIR', 'logs'),
    filename: config.get('LOG_FILE_NAME', '%DATE%.log'),
    datePattern: config.get('LOG_DATE_PATTERN', 'YYYY-MM-DD'),
    zippedArchive: config.get<boolean>('LOG_ZIPPED_ARCHIVE', true),
    maxSize: config.get('LOG_MAX_SIZE', '10m'),
    maxFiles: config.get('LOG_MAX_FILES', '14d'),
    format: fileFormat,
  });

  return [consoleTransport, fileTransport];
};
