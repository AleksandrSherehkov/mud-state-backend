export function resolveEnvFilePath(): string {
  return process.env.NODE_ENV === 'test' ? '.env.test' : '.env';
}
