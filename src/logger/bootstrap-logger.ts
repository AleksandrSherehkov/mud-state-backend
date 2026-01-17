import * as winston from 'winston';
import * as util from 'node:util';
import { getRequestId } from 'src/common/request-context/request-context';

type LogInfo = winston.Logform.TransformableInfo & {
  context?: string;
  requestId?: string;
};

function stringifyMessage(msg: unknown): string {
  if (msg === null || msg === 'undefined') return '';

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
    const timestamp = info.timestamp?.toString() ?? '';
    const level = info.level?.toString() ?? '';
    const ctx = String(info.context ?? 'App');
    const rid = info.requestId ? ` rid=${info.requestId}` : '';

    const message = stringifyMessage(info.message);

    return `[${timestamp}] ${level} [${ctx}]${rid} ${message}`.trim();
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
