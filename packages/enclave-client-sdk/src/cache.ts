export interface CachedKey {
  dek: Buffer;
  version: number;
  expiresAt: number;
}

export class KeyCache {
  private cache: Map<string, CachedKey> = new Map();
  private maxCapacity: number;
  private defaultTtlMs: number;

  constructor(maxCapacity: number = 100, defaultTtlMs: number = 5 * 60 * 1000) {
    this.maxCapacity = maxCapacity;
    this.defaultTtlMs = defaultTtlMs;
  }

  public get(keyAlias: string): CachedKey | null {
    const item = this.cache.get(keyAlias);
    if (!item) return null;

    if (Date.now() > item.expiresAt) {
      this.delete(keyAlias);
      return null;
    }

    // Refresh LRU order
    this.cache.delete(keyAlias);
    this.cache.set(keyAlias, item);

    return item;
  }

  public set(keyAlias: string, dek: Buffer, version: number, ttlMs?: number): void {
    if (this.cache.has(keyAlias)) {
      this.delete(keyAlias);
    } else if (this.cache.size >= this.maxCapacity) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey) {
        this.delete(oldestKey);
      }
    }

    const expiresAt = Date.now() + (ttlMs ?? this.defaultTtlMs);
    this.cache.set(keyAlias, { dek: Buffer.from(dek), version, expiresAt });
  }

  public delete(keyAlias: string): void {
    const item = this.cache.get(keyAlias);
    if (item) {
      item.dek.fill(0);
      this.cache.delete(keyAlias);
    }
  }

  public clear(): void {
    for (const [alias] of this.cache) {
      this.delete(alias);
    }
    this.cache.clear();
  }
}
