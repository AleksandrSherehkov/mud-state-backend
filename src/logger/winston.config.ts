import * as winston from 'winston';
import 'winston-daily-rotate-file';
import { ConfigService } from '@nestjs/config';
import { getRequestId } from 'src/common/request-context/request-context';
import * as util from 'node:util';
import { sanitizeFormat } from './formats/sanitize.format';

type LogInfo = winston.Logform.TransformableInfo & {
  context?: string;
  requestId?: string;
};

function stringifyMessage(msg: unknown): string {
  if (msg === null || msg === undefined) return '';
  if (msg instanceof Error) return msg.stack ?? msg.message;

  if (typeof msg === 'string') return msg;
  if (
    typeof msg === 'number' ||
    typeof msg === 'boolean' ||
    typeof msg === 'bigint'
  ) {
    return String(msg);
  }

  return util.inspect(msg, { depth: 10, colors: false, compact: true });
}

const addRequestId = winston.format((info: LogInfo) => {
  const rid = getRequestId();
  return rid ? { ...info, requestId: rid } : info;
});

const consoleFormat = winston.format.combine(
  sanitizeFormat(),
  addRequestId(),
  winston.format.timestamp(),
  winston.format.printf((info: LogInfo) => {
    const {
      timestamp: ts,
      level: lvl,
      message: msg,
      context,
      requestId,
      ...meta
    } = info as unknown as Record<string, unknown>;

    const timestamp = stringifyMessage(ts) || '';
    const level = stringifyMessage(lvl) || '';
    const ctx = typeof context === 'string' ? context : 'App';
    const rid = typeof requestId === 'string' ? ` rid=${requestId}` : '';

    const message = stringifyMessage(msg);

    const metaStr =
      meta && Object.keys(meta).length > 0 ? ` ${JSON.stringify(meta)}` : '';

    return `[${timestamp}] ${level} [${ctx}]${rid} ${message}${metaStr}`.trim();
  }),
);

const fileFormat = winston.format.combine(
  sanitizeFormat(),
  addRequestId(),
  winston.format.timestamp(),
  winston.format.json(),
);

export const createWinstonTransports = (
  config: ConfigService,
): winston.transport[] => {
  const env = (
    config.get<string>('APP_ENV', 'development') || 'development'
  ).toLowerCase();

  const isTest = env === 'test' || process.env.NODE_ENV === 'test';

  const consoleTransport = new winston.transports.Console({
    format: consoleFormat,

    stderrLevels: ['error'],
    handleExceptions: true,
  });

  const fileTransport = new winston.transports.DailyRotateFile({
    dirname: config.get('LOG_DIR', 'logs'),
    filename: config.get('LOG_FILE_NAME', '%DATE%.log'),
    datePattern: config.get('LOG_DATE_PATTERN', 'YYYY-MM-DD'),
    zippedArchive: config.get<boolean>('LOG_ZIPPED_ARCHIVE', true),
    maxSize: config.get('LOG_MAX_SIZE', '10m'),
    maxFiles: config.get('LOG_MAX_FILES', '14d'),
    format: fileFormat,
    handleExceptions: true,
  });

  if (isTest) return [fileTransport];

  return [consoleTransport, fileTransport];
};
