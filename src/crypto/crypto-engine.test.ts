import assert from 'node:assert';
import { test, describe } from 'node:test';
import crypto from 'node:crypto';
import { CryptoEngine } from './crypto-engine.js';
import { MasterKeyManager } from './master-key.js';

describe('CryptoEngine & MasterKeyManager Unit Tests', () => {
  const mockMasterKeyHex = crypto.randomBytes(32).toString('hex');

  test('MasterKeyManager unseals correctly with valid hex key', () => {
    process.env.KMS_MASTER_KEY = mockMasterKeyHex;
    const keyManager = new MasterKeyManager();
    assert.strictEqual(keyManager.isUnsealed(), true);
    assert.strictEqual(keyManager.getMasterKey().length, 32);
    keyManager.shutdown();
  });

  test('CryptoEngine performs envelope DEK encryption and decryption', () => {
    const masterKey = Buffer.from(mockMasterKeyHex, 'hex');
    const dek = CryptoEngine.generateDEK();

    const encryptedDek = CryptoEngine.encryptWithMasterKey(dek, masterKey);
    assert.notDeepStrictEqual(encryptedDek.encryptedDek, dek);

    const decryptedDek = CryptoEngine.decryptWithMasterKey(
      encryptedDek.encryptedDek,
      encryptedDek.iv,
      encryptedDek.authTag,
      masterKey
    );

    assert.deepStrictEqual(decryptedDek, dek);
  });

  test('CryptoEngine encrypts and decrypts payload data correctly', () => {
    const dek = CryptoEngine.generateDEK();
    const plaintext = Buffer.from('Sensitive User PII Data');

    const encrypted = CryptoEngine.encryptPayload(plaintext, dek);
    const decrypted = CryptoEngine.decryptPayload(
      encrypted.ciphertext,
      encrypted.iv,
      encrypted.authTag,
      dek
    );

    assert.strictEqual(decrypted.toString('utf-8'), 'Sensitive User PII Data');
  });

  test('CryptoEngine rejects tampered payload authentication tag', () => {
    const dek = CryptoEngine.generateDEK();
    const plaintext = Buffer.from('Tamper Test');
    const encrypted = CryptoEngine.encryptPayload(plaintext, dek);

    encrypted.authTag[0] ^= 0xff;

    assert.throws(() => {
      CryptoEngine.decryptPayload(
        encrypted.ciphertext,
        encrypted.iv,
        encrypted.authTag,
        dek
      );
    });
  });
});
