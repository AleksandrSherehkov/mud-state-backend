import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import type { ScryptOptions } from 'node:crypto';

const REFRESH_SALT_BYTES = 16;
const SCRYPT_KEYLEN = 32;
const SCRYPT_OPTS: ScryptOptions = {
  N: 1 << 15,
  r: 8,
  p: 1,
  maxmem: 128 * 1024 * 1024,
};

function scryptAsync(
  password: string | Buffer,
  salt: string | Buffer,
  keylen: number,
  options: ScryptOptions,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, keylen, options, (err, derivedKey) => {
      if (err) return reject(err);
      resolve(derivedKey as Buffer);
    });
  });
}

@Injectable()
export class RefreshTokenHashService {
  constructor(private readonly config: ConfigService) {}

  generateSaltHex(): string {
    return randomBytes(REFRESH_SALT_BYTES).toString('hex');
  }

  async hash(refreshToken: string, salt?: string | null): Promise<string> {
    if (!salt) {
      throw new Error(
        'Refresh token hashing invariant violated: tokenSalt is missing (legacy hashing is disabled)',
      );
    }

    const pepper = this.getPepper();
    const s = `${pepper}:${salt}`;

    // async scrypt -> libuv threadpool (не блочит event-loop)
    const dk = await scryptAsync(refreshToken, s, SCRYPT_KEYLEN, SCRYPT_OPTS);
    return dk.toString('hex');
  }

  safeEqualHex(a: string, b: string): boolean {
    if (!a || !b) return false;
    if (a.length !== b.length) return false;
    if (a.length % 2 !== 0) return false;

    const ba = Buffer.from(a, 'hex');
    const bb = Buffer.from(b, 'hex');
    if (ba.length !== bb.length) return false;

    return timingSafeEqual(ba, bb);
  }

  private getPepper(): string {
    const pepper = (
      this.config.get<string>('REFRESH_TOKEN_PEPPER') ?? ''
    ).trim();
    if (!pepper) throw new Error('REFRESH_TOKEN_PEPPER is not set');
    return pepper;
  }
}
