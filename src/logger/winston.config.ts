import * as winston from 'winston';
import 'winston-daily-rotate-file';
import { ConfigService } from '@nestjs/config';
import { getRequestId } from 'src/common/request-context/request-context';
import * as util from 'node:util';

type LogInfo = winston.Logform.TransformableInfo & {
  context?: string;
  requestId?: string;
};

function stringifyMessage(msg: unknown): string {
  if (msg === null || msg === 'undefined') return '';

  if (msg instanceof Error) {
    return msg.stack ?? msg.message;
  }

  if (typeof msg === 'string') return msg;
  if (
    typeof msg === 'number' ||
    typeof msg === 'boolean' ||
    typeof msg === 'bigint'
  )
    return String(msg);

  return util.inspect(msg, { depth: 10, colors: false, compact: true });
}

const addRequestId = winston.format((info: LogInfo) => {
  const rid = getRequestId();
  return rid ? { ...info, requestId: rid } : info;
});

const consoleFormat = winston.format.combine(
  addRequestId(),
  winston.format.colorize(),
  winston.format.timestamp(),
  winston.format.printf((info: LogInfo) => {
    const timestamp = info.timestamp?.toString() ?? '';
    const level = info.level?.toString() ?? '';
    const ctx = String(info.context ?? 'App');
    const rid = info.requestId ? ` rid=${info.requestId}` : '';

    const message = stringifyMessage(info.message);

    return `[${timestamp}] ${level} [${ctx}]${rid} ${message}`.trim();
  }),
);

const fileFormat = winston.format.combine(
  addRequestId(),
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
