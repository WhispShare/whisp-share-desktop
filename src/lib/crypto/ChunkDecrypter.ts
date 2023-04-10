import { TransformCallback } from 'stream';
import ChunkCrypter from './ChunkCrypter';
import { aesgcmDecrypt } from './aesgcm';

class ChunkDecrypter extends ChunkCrypter {
  constructor(key: Buffer, additionalData: Buffer) {
    super(key, additionalData);
  }

  _transform(encryptedChunk: Buffer, _encoding: BufferEncoding, done: TransformCallback): void {
    const nonce = encryptedChunk.subarray(0, 12);
    const ciphertext = encryptedChunk.subarray(12, -16);
    const authTag = encryptedChunk.subarray(-16);
    try {
      const chunk = aesgcmDecrypt(ciphertext, authTag, this.key, nonce, this.additionalData);
      this.push(chunk);
      super._transform(encryptedChunk, _encoding, done);
    } catch (error: unknown) {
      this.push(null);
      this.emit('error', error as Error);
      done();
    }
  }
}

export default ChunkDecrypter;
