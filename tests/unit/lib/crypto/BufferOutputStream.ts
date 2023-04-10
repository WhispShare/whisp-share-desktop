import { Writable } from 'stream';

class BufferOutputStream extends Writable {
  public buffer = Buffer.alloc(0);

  _write(chunk: Buffer, _encoding: BufferEncoding, done: (error?: Error | null | undefined) => void): void {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    done();
  }
}

export default BufferOutputStream;
