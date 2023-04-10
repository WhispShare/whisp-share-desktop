import { aesgcmEncrypt, aesgcmDecrypt, aesKeyGen, aesNonceGen } from '@/lib/crypto/aesgcm';
import { key, nonce, data, additionalData, ciphertext, authTag } from './aesgcmTestvector';
import { assert } from 'assertthat';

jest.mock('crypto', () => {
  const originalModule = jest.requireActual('crypto');
  return {
    ...originalModule,
    randomBytes(size: number): Buffer {
      const buffer = Buffer.alloc(size);
      buffer.fill(size);
      return buffer;
    }
  };
});

const authErrorMessage = 'Unsupported state or unable to authenticate data';

describe('AES-GCM', (): void => {
  test('encrypts correctly.', async (): Promise<void> => {
    const [actualCiphertext, actualAuthTag] = aesgcmEncrypt(data, key, nonce, additionalData);

    assert.that(actualCiphertext).is.equalTo(ciphertext);
    assert.that(actualAuthTag).is.equalTo(authTag);
  });

  test('decrypts correctly.', async (): Promise<void> => {
    const acualDecrypted = aesgcmDecrypt(ciphertext, authTag, key, nonce, additionalData);

    assert.that(acualDecrypted).is.equalTo(data);
  });

  test('returns 32 bytes buffer, all bytes 0010000.', async (): Promise<void> => {
    const bytes = aesKeyGen();

    assert.that(bytes).is.equalTo(Buffer.from('20'.repeat(32), 'hex'));
  });

  test('returns 12 bytes buffer, all bytes 00001100.', async (): Promise<void> => {
    const bytes = aesNonceGen();

    assert.that(bytes).is.equalTo(Buffer.from('0C'.repeat(12), 'hex'));
  });

  describe('fails decryption due to invalid...', (): void => {
    const tamper = (source: Buffer, bytePos = 0): Buffer => {
      const tampered = Buffer.concat([source]);
      // flip last bit of bytePos byte
      tampered[bytePos] = tampered[bytePos] ^ 1;
      return tampered;
    };

    test('...ciphertext.', async (): Promise<void> => {
      const tampered = tamper(ciphertext);

      assert
        .that((): void => {
          aesgcmDecrypt(tampered, authTag, key, nonce, additionalData);
        })
        .is.throwing(authErrorMessage);
    });

    test('...nonce.', async (): Promise<void> => {
      const tampered = tamper(nonce);

      assert
        .that((): void => {
          aesgcmDecrypt(ciphertext, authTag, key, tampered, additionalData);
        })
        .is.throwing(authErrorMessage);
    });

    test('...additionalData.', async (): Promise<void> => {
      const tampered = tamper(additionalData);

      assert
        .that((): void => {
          aesgcmDecrypt(ciphertext, authTag, key, nonce, tampered);
        })
        .is.throwing(authErrorMessage);
    });

    test('...key.', async (): Promise<void> => {
      const tampered = tamper(key);

      assert
        .that((): void => {
          aesgcmDecrypt(ciphertext, authTag, tampered, nonce, additionalData);
        })
        .is.throwing(authErrorMessage);
    });

    test('...authTag.', async (): Promise<void> => {
      const tampered = tamper(authTag);

      assert
        .that((): void => {
          aesgcmDecrypt(ciphertext, tampered, key, nonce, additionalData);
        })
        .is.throwing(authErrorMessage);
    });
  });
});
