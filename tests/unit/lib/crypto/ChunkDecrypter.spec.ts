import ChunkDecrypter from '@/lib/crypto/ChunkDecrypter';
import { key, nonce, data, additionalData, ciphertext, authTag } from './aesgcmTestvector';
import BufferOutputStream from './BufferOutputStream';
import { Readable, pipeline } from 'stream';
import { assert } from 'assertthat';

const authErrorMessage = 'Unsupported state or unable to authenticate data';

describe('Chunk Decrypter', (): void => {
  test('decrypts chunk correctly.', async (): Promise<void> => {
    const input = Readable.from(Buffer.concat([nonce, ciphertext, authTag]));
    const output = new BufferOutputStream();
    const decrypter = new ChunkDecrypter(key, additionalData);

    pipeline(input, decrypter, output, (error: unknown): void => {
      assert.that(output.buffer).is.equalTo(data);
      assert.that(error).is.undefined();
    });
  });

  describe('fails due to invalid...', (): void => {
    const tamper = (source: Buffer, bytePos = 0): Buffer => {
      const tampered = Buffer.concat([source]);
      // flip last bit of bytePos byte
      tampered[bytePos] = tampered[bytePos] ^ 1;
      return tampered;
    };

    test('...nonce.', async (): Promise<void> => {
      const tampered = tamper(nonce);
      const input = Readable.from(Buffer.concat([tampered, ciphertext, authTag]));
      const output = new BufferOutputStream();
      const decrypter = new ChunkDecrypter(key, additionalData);

      pipeline(input, decrypter, output, (error: unknown): void => {
        assert.that(error).is.not.undefined();
        assert.that(error).is.not.null();
        assert.that((error as Error).message).is.equalTo(authErrorMessage);
      });
    });

    test('...ciphertext.', async (): Promise<void> => {
      const tampered = tamper(ciphertext);
      const input = Readable.from(Buffer.concat([nonce, tampered, authTag]));
      const output = new BufferOutputStream();
      const decrypter = new ChunkDecrypter(key, additionalData);

      pipeline(input, decrypter, output, (error: unknown): void => {
        assert.that(error).is.not.undefined();
        assert.that(error).is.not.null();
        assert.that((error as Error).message).is.equalTo(authErrorMessage);
      });
    });

    test('...id (like on renaming- or swap-contents-attack).', async (): Promise<void> => {
      const tampered = tamper(additionalData);
      const input = Readable.from(Buffer.concat([nonce, ciphertext, authTag]));
      const output = new BufferOutputStream();
      const decrypter = new ChunkDecrypter(key, tampered);

      pipeline(input, decrypter, output, (error: unknown): void => {
        assert.that(error).is.not.undefined();
        assert.that(error).is.not.null();
        assert.that((error as Error).message).is.equalTo(authErrorMessage);
      });
    });

    test('...index (like on re-ordering attack).', async (): Promise<void> => {
      const tampered = tamper(additionalData, additionalData.length - 1);
      const input = Readable.from(Buffer.concat([nonce, ciphertext, authTag]));
      const output = new BufferOutputStream();
      const decrypter = new ChunkDecrypter(key, tampered);

      pipeline(input, decrypter, output, (error: unknown): void => {
        assert.that(error).is.not.undefined();
        assert.that(error).is.not.null();
        assert.that((error as Error).message).is.equalTo(authErrorMessage);
      });
    });

    test('...authTag.', async (): Promise<void> => {
      const tampered = tamper(authTag);
      const input = Readable.from(Buffer.concat([nonce, ciphertext, tampered]));
      const output = new BufferOutputStream();
      const decrypter = new ChunkDecrypter(key, additionalData);

      pipeline(input, decrypter, output, (error: unknown): void => {
        assert.that(error).is.not.undefined();
        assert.that(error).is.not.null();
        assert.that((error as Error).message).is.equalTo(authErrorMessage);
      });
    });

    test('...key.', async (): Promise<void> => {
      const tampered = tamper(key);
      const input = Readable.from(Buffer.concat([nonce, ciphertext, authTag]));
      const output = new BufferOutputStream();
      const decrypter = new ChunkDecrypter(tampered, additionalData);

      pipeline(input, decrypter, output, (error: unknown): void => {
        assert.that(error).is.not.undefined();
        assert.that(error).is.not.null();
        assert.that((error as Error).message).is.equalTo(authErrorMessage);
      });
    });
  });
});
