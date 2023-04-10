import { Transform, TransformCallback } from 'stream';

abstract class ChunkCrypter extends Transform {
  key: Buffer;
  additionalData: Buffer;

  constructor(key: Buffer, additionalData: Buffer) {
    super();
    this.key = key;
    this.additionalData = additionalData;
  }

  _transform(_chunk: Buffer, _encoding: BufferEncoding, done: TransformCallback): void {
    const offset = this.additionalData.length - 1;
    this._increaseIndex(offset);
    done();
  }

  _increaseIndex(offset: number): void {
    const newByte = this.additionalData[offset] + 1;
    if (newByte < 256) {
      this.additionalData[offset] = newByte;
      return;
    }
    this.additionalData[offset] = 0;
    this._increaseIndex(offset - 1);
  }
}

export default ChunkCrypter;
