import * as winston from 'winston';

export const consoleTransport = new winston.transports.Console({
  format: winston.format.combine(
    winston.format.colorize(),
    winston.format.timestamp(),
    winston.format.printf(
      ({
        timestamp,
        level,
        message,
        context,
      }: {
        timestamp?: string;
        level: string;
        message: string;
        context?: string;
      }) => {
        const ctx = context || 'App';
        return `[${timestamp}] ${level} [${ctx}] ${message}`;
      },
    ),
  ),
});

export const fileTransport = new winston.transports.DailyRotateFile({
  dirname: 'logs',
  filename: '%DATE%.log',
  datePattern: 'YYYY-MM-DD',
  zippedArchive: true,
  maxSize: '10m',
  maxFiles: '14d',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json(),
  ),
});
