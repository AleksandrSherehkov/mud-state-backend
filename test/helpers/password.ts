export function envBool(v: unknown, def = false): boolean {
  if (typeof v !== 'string') return def;
  const s = v.trim().toLowerCase();
  if (s === 'true') return true;
  if (s === 'false') return false;
  return def;
}

export function envInt(v: unknown, def: number): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : def;
}

export function buildValidPassword(): string {
  const min = envInt(process.env.PASSWORD_MIN_LENGTH, 8);
  const max = envInt(process.env.PASSWORD_MAX_LENGTH, 72);

  const requireUpper = envBool(process.env.PASSWORD_REQUIRE_UPPERCASE, true);
  const requireDigit = envBool(process.env.PASSWORD_REQUIRE_DIGIT, true);
  const requireSpecial = envBool(process.env.PASSWORD_REQUIRE_SPECIAL, false);

  let pwd = 'a';
  if (requireUpper) pwd += 'A';
  if (requireDigit) pwd += '1';
  if (requireSpecial) pwd += '!';

  while (pwd.length < min) pwd += 'x';
  if (pwd.length > max) pwd = pwd.slice(0, max);

  return pwd;
}
