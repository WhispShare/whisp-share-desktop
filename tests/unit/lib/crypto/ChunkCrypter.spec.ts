import ChunkCrypter from '@/lib/crypto/ChunkCrypter';
import { assert } from 'assertthat';
import { TransformCallback } from 'stream';

class ChunkTestCrypter extends ChunkCrypter {
  constructor(key: Buffer, additionalData: Buffer) {
    super(key, additionalData);
  }

  _transform(_chunk: Buffer, _encoding: BufferEncoding, done: TransformCallback): void {
    done();
  }

  public increaseAndGetIndex(startIndex: Uint8Array): Uint8Array {
    this.additionalData = Buffer.from(startIndex);
    this._increaseIndex(this.additionalData.length - 1);
    return new Uint8Array(this.additionalData);
  }

  public getKey(): Buffer {
    return this.key;
  }

  public getAdditionalData(): Buffer {
    return this.additionalData;
  }
}

describe('Chunk Crypter', (): void => {
  test('constructs correctly.', async (): Promise<void> => {
    const key = Buffer.from(new Uint8Array([42, 23]));
    const additionalData = Buffer.from(new Uint8Array([1, 2, 3, 4, 5]));
    const testCrypter = new ChunkTestCrypter(key, additionalData);

    assert.that(testCrypter.getKey()).is.equalTo(key);
    assert.that(testCrypter.getAdditionalData()).is.equalTo(additionalData);
  });

  describe('increases index correctly...', (): void => {
    const vector = [
      { start: [42, 0, 0, 0, 7], target: [42, 0, 0, 0, 8] },
      { start: [42, 0, 0, 19, 255], target: [42, 0, 0, 20, 0] },
      { start: [42, 0, 4, 255, 255], target: [42, 0, 5, 0, 0] },
      { start: [42, 70, 255, 255, 255], target: [42, 71, 0, 0, 0] },
      { start: [42, 254, 255, 255, 255], target: [42, 255, 0, 0, 0] }
    ];

    for (const { start, target } of vector) {
      test(`...from [${start}] to [${target}]`, async (): Promise<void> => {
        const testCrypter = new ChunkTestCrypter(Buffer.alloc(0), Buffer.alloc(0));

        const actualTarget = testCrypter.increaseAndGetIndex(new Uint8Array(start));

        assert.that(actualTarget).is.equalTo(new Uint8Array(target));
      });
    }
  });
});
