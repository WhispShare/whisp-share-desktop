import ChunkEncrypter from '@/lib/crypto/ChunkEncrypter';
import { key, nonce, data, additionalData, ciphertext, authTag } from './aesgcmTestvector';
import BufferOutputStream from './BufferOutputStream';
import { Readable, pipeline } from 'stream';
import { assert } from 'assertthat';

jest.mock('crypto', () => {
  const originalModule = jest.requireActual('crypto');
  const { nonce } = jest.requireActual('./aesgcmTestvector');
  return {
    ...originalModule,
    randomBytes(size: number): Buffer {
      return size === 12 ? nonce : originalModule.randomBytes(size);
    }
  };
});

describe('Chunk Encrypter', (): void => {
  test('encrypts chunk correctly.', async (): Promise<void> => {
    const input = Readable.from(data);
    const output = new BufferOutputStream();
    const encrypter = new ChunkEncrypter(key, additionalData);

    pipeline(input, encrypter, output, (error: unknown): void => {
      assert.that(output.buffer).is.equalTo(Buffer.concat([nonce, ciphertext, authTag]));
      assert.that(error).is.undefined();
    });
  });
});
