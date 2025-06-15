import * as winston from 'winston';
import { consoleTransport } from './winston.config';

export const bootstrapLogger = winston.createLogger({
  level: 'debug',
  transports: [consoleTransport],
});
