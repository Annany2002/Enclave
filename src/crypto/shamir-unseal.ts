import crypto from 'node:crypto';

export interface SecretShare {
  index: number;
  shareHex: string;
}

/**
 * Multi-operator secret sharing engine for splitting and unsealing the Master Key.
 * 
 * @remark **Secret Share Prefix**: `enc_shr_X_` (e.g. `enc_shr_1_a7ed9c3442451e87...`)
 */
export class ShamirUnsealEngine {
  /**
   * Splits a 256-bit Master Key into N random secret shares.
   * 
   * @remark **Secret Share Prefix**: `enc_shr_X_`
   */
  public static splitMasterKey(masterKeyHex: string, totalShares: number = 3): SecretShare[] {
    const cleanMasterHex = masterKeyHex.replace(/^enc_kek_/, '');
    const keyBuffer = Buffer.from(cleanMasterHex, 'hex');
    if (keyBuffer.length !== 32) {
      throw new Error('Master key must be 32 bytes (64 hex characters).');
    }

    const shares: SecretShare[] = [];
    const accumXor = Buffer.alloc(32);

    for (let i = 1; i < totalShares; i++) {
      const randomShare = crypto.randomBytes(32);
      for (let b = 0; b < 32; b++) {
        accumXor[b] ^= randomShare[b];
      }
      shares.push({ index: i, shareHex: `enc_shr_${i}_${randomShare.toString('hex')}` });
    }

    const finalShare = Buffer.alloc(32);
    for (let b = 0; b < 32; b++) {
      finalShare[b] = keyBuffer[b] ^ accumXor[b];
    }
    shares.push({ index: totalShares, shareHex: `enc_shr_${totalShares}_${finalShare.toString('hex')}` });

    return shares;
  }

  /**
   * Reconstructs the 256-bit Master Key from N secret shares (supports `enc_shr_` prefixed or raw shares).
   */
  public static combineShares(shares: SecretShare[]): string {
    if (shares.length === 0) {
      throw new Error('No secret shares provided.');
    }

    const reconstructed = Buffer.alloc(32);
    for (const share of shares) {
      const cleanHex = share.shareHex.replace(/^enc_shr_\d+_/, '');
      const shareBuf = Buffer.from(cleanHex, 'hex');
      for (let b = 0; b < 32; b++) {
        reconstructed[b] ^= shareBuf[b];
      }
    }

    return reconstructed.toString('hex');
  }
}
