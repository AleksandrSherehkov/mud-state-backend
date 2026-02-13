import { Injectable, ServiceUnavailableException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  createHmac,
  randomBytes,
  scrypt,
  timingSafeEqual,
  type BinaryLike,
} from 'node:crypto';

const REFRESH_SALT_BYTES = 16;
const SCRYPT_KEYLEN = 32;
const SCRYPT_OPTS = { N: 1 << 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 };

type QueueTask<T> = () => Promise<T>;

@Injectable()
export class RefreshTokenHashService {
  private readonly maxConcurrent: number;
  private readonly maxQueue: number;
  private active = 0;
  private queue: Array<() => void> = [];

  constructor(private readonly config: ConfigService) {
    this.maxConcurrent = Number(
      this.config.get('REFRESH_HASH_MAX_CONCURRENCY') ?? 8,
    );
    this.maxQueue = Number(this.config.get('REFRESH_HASH_MAX_QUEUE') ?? 200);
  }

  generateSaltHex(): string {
    return randomBytes(REFRESH_SALT_BYTES).toString('hex');
  }

  async hash(refreshToken: string, salt?: string | null): Promise<string> {
    if (!salt) return this.hashLegacy(refreshToken);

    const pepper = this.getPepper();
    const s = `${pepper}:${salt}`;

    const dk = await this.runWithBackpressure(() =>
      this.scryptAsync(refreshToken, s, SCRYPT_KEYLEN),
    );

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

  private async scryptAsync(
    password: BinaryLike,
    salt: BinaryLike,
    keylen: number,
  ): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      scrypt(password, salt, keylen, SCRYPT_OPTS, (err, derivedKey) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(derivedKey as Buffer);
      });
    });
  }

  private async runWithBackpressure<T>(task: QueueTask<T>): Promise<T> {
    if (
      this.active >= this.maxConcurrent &&
      this.queue.length >= this.maxQueue
    ) {
      throw new ServiceUnavailableException('refresh_hash_busy');
    }

    await this.acquire();
    try {
      return await task();
    } finally {
      this.release();
    }
  }

  private async acquire(): Promise<void> {
    if (this.active < this.maxConcurrent) {
      this.active += 1;
      return;
    }

    await new Promise<void>((resolve) => {
      this.queue.push(() => {
        this.active += 1;
        resolve();
      });
    });
  }

  private release(): void {
    this.active = Math.max(0, this.active - 1);
    const next = this.queue.shift();
    if (next) next();
  }
}
