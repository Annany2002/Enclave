import { IStorageAdapter } from '../storage/storage-adapter.js';
import { MasterKeyManager } from './master-key.js';
import { CryptoEngine } from './crypto-engine.js';
import { WebhookDispatcher } from '../webhooks/webhook-dispatcher.js';

/**
 * Background worker service that monitors Data Encryption Keys (DEKs) and automatically rotates expired keys.
 */
export class KeyRotatorWorker {
  private timer: NodeJS.Timeout | null = null;
  private maxAgeMs: number;
  private checkIntervalMs: number;

  constructor(
    private storage: IStorageAdapter,
    private keyManager: MasterKeyManager,
    private webhooks?: WebhookDispatcher
  ) {
    const maxAgeDays = Number(process.env.ENCLAVE_KEY_MAX_AGE_DAYS) || 90;
    this.maxAgeMs = maxAgeDays * 24 * 60 * 60 * 1000;
    this.checkIntervalMs = Number(process.env.ENCLAVE_ROTATION_CHECK_INTERVAL_MS) || 24 * 60 * 60 * 1000;
  }

  /**
   * Starts the background rotation check timer.
   */
  public start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => {
      this.performRotationCheck().catch(() => {});
    }, this.checkIntervalMs);
  }

  /**
   * Stops the background rotation check timer cleanly.
   */
  public stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  /**
   * Evaluates key age across storage adapter and rotates expired DEKs.
   * @returns Count of auto-rotated keys.
   */
  public async performRotationCheck(): Promise<number> {
    if (!this.keyManager.isUnsealed()) {
      return 0;
    }

    let rotatedCount = 0;
    const now = Date.now();
    const keys = await this.storage.listKeys();

    for (const keyRecord of keys) {
      if (keyRecord.state !== 'ENABLED') continue;

      const updatedAtTime = new Date(keyRecord.updatedAt).getTime();
      const ageMs = now - updatedAtTime;

      if (ageMs >= this.maxAgeMs) {
        try {
          const newRawDek = CryptoEngine.generateDEK();
          const masterKey = this.keyManager.getMasterKey();
          const newEncryptedDek = CryptoEngine.encryptWithMasterKey(newRawDek, masterKey);

          await this.storage.updateKey(keyRecord.id, newEncryptedDek, keyRecord.version + 1);

          CryptoEngine.zeroBuffer(newRawDek);
          rotatedCount++;

          await this.storage.logAudit({
            serviceId: 'system-auto-rotator',
            action: 'AutoRotateKey',
            keyId: keyRecord.id,
            status: 'SUCCESS',
            ipAddress: '127.0.0.1',
          });

          if (this.webhooks) {
            this.webhooks.dispatch({
              event: 'RotateKey',
              timestamp: new Date().toISOString(),
              serviceId: 'system-auto-rotator',
              keyAlias: keyRecord.alias,
              status: 'SUCCESS',
              ipAddress: '127.0.0.1',
            });
          }
        } catch (err) {
          // Continue rotating remaining keys
        }
      }
    }

    return rotatedCount;
  }
}
