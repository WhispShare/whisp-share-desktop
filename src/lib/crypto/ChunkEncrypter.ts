import { TransformCallback } from 'stream';
import ChunkCrypter from './ChunkCrypter';
import { aesgcmEncrypt, aesNonceGen } from './aesgcm';

class ChunkEncrypter extends ChunkCrypter {
  constructor(key: Buffer, additionalData: Buffer) {
    super(key, additionalData);
  }

  _transform(chunk: Buffer, _encoding: BufferEncoding, done: TransformCallback): void {
    const nonce = aesNonceGen();
    const [ciphertext, authTag] = aesgcmEncrypt(chunk, this.key, nonce, this.additionalData);
    this.push(Buffer.concat([nonce, ciphertext, authTag]));
    super._transform(chunk, _encoding, done);
  }
}

export default ChunkEncrypter;
