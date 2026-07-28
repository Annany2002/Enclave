/**
 * Manages the unsealing, validation, and zero-fill destruction of the Master Key (KEK).
 * 
 * @remark **Master KEK Prefix**: `enc_kek_` (e.g. `enc_kek_d6e0020a1769bba9...`)
 */
export class MasterKeyManager {
  private masterKey: Buffer | null = null;

  constructor() {
    this.bootstrapMasterKey();
  }

  private bootstrapMasterKey(): void {
    const envKey = process.env.ENCLAVE_MASTER_KEY || process.env.KMS_MASTER_KEY;
    if (!envKey) {
      throw new Error('FATAL: ENCLAVE_MASTER_KEY environment variable is not defined.');
    }

    const cleanKeyHex = envKey.replace(/^enc_kek_/, '');
    const keyBuf = Buffer.from(cleanKeyHex, 'hex');
    if (keyBuf.length !== 32) {
      keyBuf.fill(0);
      throw new Error(`FATAL: ENCLAVE_MASTER_KEY must be exactly 256 bits (64 hex chars). Received ${cleanKeyHex.length} chars.`);
    }

    this.masterKey = keyBuf;
  }

  /**
   * Retrieves the unsealed Master Key buffer.
   * Throws if the server is in a sealed or uninitialized state.
   */
  public getMasterKey(): Buffer {
    if (!this.masterKey) {
      throw new Error('FATAL: Enclave Master Key is not unsealed or ready.');
    }
    return this.masterKey;
  }

  /**
   * Returns true if the Master Key is in memory and validated.
   */
  public isUnsealed(): boolean {
    return this.masterKey !== null && this.masterKey.length === 32;
  }

  /**
   * Scrubs the Master Key buffer with zeros before releasing reference.
   */
  public shutdown(): void {
    if (this.masterKey) {
      this.masterKey.fill(0);
      this.masterKey = null;
    }
  }
}
