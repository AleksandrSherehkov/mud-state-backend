import { format } from 'winston';
import { sanitizeMeta, sanitizeString } from 'src/common/helpers/log-sanitize';

export const sanitizeFormat = format((info) => {
  info.message = sanitizeString(String(info.message));

  // НЕ чіпаємо level/timestamp
  const { level, message, ...rest } = info;

  const cleaned = sanitizeMeta(rest);

  return { level, message, ...cleaned };
});
