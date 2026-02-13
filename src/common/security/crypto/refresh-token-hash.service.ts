import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  createHmac,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from 'node:crypto';

const REFRESH_SALT_BYTES = 16;
const SCRYPT_KEYLEN = 32;
const SCRYPT_OPTS = { N: 1 << 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 };

@Injectable()
export class RefreshTokenHashService {
  constructor(private readonly config: ConfigService) {}

  generateSaltHex(): string {
    return randomBytes(REFRESH_SALT_BYTES).toString('hex');
  }

  hash(refreshToken: string, salt?: string | null): string {
    if (!salt) return this.hashLegacy(refreshToken);

    const pepper = this.getPepper();
    const s = `${pepper}:${salt}`;

    const dk = scryptSync(refreshToken, s, SCRYPT_KEYLEN, SCRYPT_OPTS);
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

  private hashLegacy(token: string): string {
    const pepper = this.getPepper();
    return createHmac('sha256', pepper).update(token).digest('hex');
  }

  private getPepper(): string {
    const pepper = (
      this.config.get<string>('REFRESH_TOKEN_PEPPER') ?? ''
    ).trim();
    if (!pepper) throw new Error('REFRESH_TOKEN_PEPPER is not set');
    return pepper;
  }
}
