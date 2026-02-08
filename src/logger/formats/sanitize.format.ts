import { format } from 'winston';
import { sanitizeMeta, sanitizeString } from 'src/common/helpers/log-sanitize';

export const sanitizeFormat = format((info) => {
  const safeMessage = sanitizeString(
    typeof info.message === 'string' ? info.message : String(info.message),
  );

  const level =
    typeof info.level === 'string' ? info.level : String(info.level);

  const { level: __level, message: __message, ...rest } = info;

  const cleaned = sanitizeMeta(rest) as Record<string, unknown>;

  return { ...cleaned, level, message: safeMessage };
});
