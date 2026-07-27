import crypto from 'node:crypto';

export interface EncryptedPayload {
  ciphertext: Buffer;
  iv: Buffer;
  authTag: Buffer;
}

export interface EncryptedDEK {
  encryptedDek: Buffer;
  iv: Buffer;
  authTag: Buffer;
}

export class CryptoEngine {
  private static ALGORITHM = 'aes-256-gcm';
  private static IV_LENGTH = 12;
  private static AUTH_TAG_LENGTH = 16;
  private static KEY_LENGTH = 32;

  public static generateDEK(): Buffer {
    return crypto.randomBytes(this.KEY_LENGTH);
  }

  public static zeroBuffer(buf: Buffer): void {
    buf.fill(0);
  }

  public static encryptWithMasterKey(dek: Buffer, masterKey: Buffer): EncryptedDEK {
    const iv = crypto.randomBytes(this.IV_LENGTH);
    const cipher = crypto.createCipheriv(this.ALGORITHM, masterKey, iv, {
      authTagLength: this.AUTH_TAG_LENGTH,
    } as crypto.CipherGCMOptions) as crypto.CipherGCM;

    const encryptedDek = Buffer.concat([cipher.update(dek), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return { encryptedDek, iv, authTag };
  }

  public static decryptWithMasterKey(
    encryptedDek: Buffer,
    iv: Buffer,
    authTag: Buffer,
    masterKey: Buffer
  ): Buffer {
    const decipher = crypto.createDecipheriv(this.ALGORITHM, masterKey, iv, {
      authTagLength: this.AUTH_TAG_LENGTH,
    } as crypto.CipherGCMOptions) as crypto.DecipherGCM;
    decipher.setAuthTag(authTag);

    return Buffer.concat([decipher.update(encryptedDek), decipher.final()]);
  }

  public static encryptPayload(plaintext: Buffer, dek: Buffer): EncryptedPayload {
    const iv = crypto.randomBytes(this.IV_LENGTH);
    const cipher = crypto.createCipheriv(this.ALGORITHM, dek, iv, {
      authTagLength: this.AUTH_TAG_LENGTH,
    } as crypto.CipherGCMOptions) as crypto.CipherGCM;

    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return { ciphertext, iv, authTag };
  }

  public static decryptPayload(
    ciphertext: Buffer,
    iv: Buffer,
    authTag: Buffer,
    dek: Buffer
  ): Buffer {
    const decipher = crypto.createDecipheriv(this.ALGORITHM, dek, iv, {
      authTagLength: this.AUTH_TAG_LENGTH,
    } as crypto.CipherGCMOptions) as crypto.DecipherGCM;
    decipher.setAuthTag(authTag);

    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }

  public static timingSafeCompare(a: string, b: string): boolean {
    const bufA = Buffer.from(a);
    const bufB = Buffer.from(b);
    if (bufA.length !== bufB.length) {
      return false;
    }
    return crypto.timingSafeEqual(bufA, bufB);
  }
}
