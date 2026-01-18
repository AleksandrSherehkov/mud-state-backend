import * as winston from 'winston';
import * as util from 'node:util';
import { getRequestId } from 'src/common/request-context/request-context';

type LogInfo = winston.Logform.TransformableInfo & {
  context?: string;
  requestId?: string;
};

function stringifyMessage(msg: unknown): string {
  if (msg === null || typeof msg === 'undefined') return '';
  if (msg instanceof Error) return msg.stack ?? msg.message;

  if (typeof msg === 'string') return msg;
  if (
    typeof msg === 'number' ||
    typeof msg === 'boolean' ||
    typeof msg === 'bigint'
  ) {
    return String(msg);
  }

  return util.inspect(msg, { depth: 6, colors: false, compact: true });
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

const isTest = process.env.NODE_ENV === 'test';

export const bootstrapLogger = winston.createLogger({
  level: 'debug',
  transports: isTest
    ? []
    : [
        new winston.transports.Console({
          format: consoleFormat,
        }),
      ],
});
