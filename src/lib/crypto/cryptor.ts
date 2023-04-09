import { Readable, Writable } from 'stream';
import { chunkSize } from './properties';
import { aesgcmEncrypt, aesKeyGen, aesNonceGen } from './aesgcm';
import ProgressCallback from '@/types/ProgressCallback';

let progressCallback: ProgressCallback | null = null;
let bytesTotal = 0;
let bytesWritten = 0;

const setProgressCallback = (bytesTotalToSet: number, progressCallbackToSet?: ProgressCallback): void => {
  if (!progressCallbackToSet) {
    return;
  }

  bytesTotal = bytesTotalToSet;
  progressCallback = progressCallbackToSet;
  progressCallback(0);
};

const setStreamsInfinityMaxListeners = (input: Readable, output: Writable): void => {
  input.setMaxListeners(Infinity);
  output.setMaxListeners(Infinity);
};

const writeBufferToOutput = (buffer: Buffer, output: Writable, resolve: () => void): void => {
  output.write(buffer, (): void => {
    if (progressCallback) {
      bytesWritten += buffer.length;
      const percent = bytesWritten === bytesTotal ? 100 : (100 / bytesTotal) * bytesWritten;
      progressCallback(percent);
    }
  });
  resolve();
};

const writeBufferToOutputWhenReady = (buffer: Buffer, output: Writable): Promise<void> => {
  return new Promise((resolve) => {
    if (output.writableNeedDrain) {
      output.once('drain', (): void => {
        writeBufferToOutput(buffer, output, resolve);
      });
    } else {
      writeBufferToOutput(buffer, output, resolve);
    }
  });
};

const endStreams = (input: Readable, output: Writable, resolve: () => void): void => {
  output.end((): void => {
    input.destroy();
    output.destroy();
    resolve();
  });
};

const endStreamsWhenReady = (input: Readable, output: Writable): Promise<void> => {
  return new Promise((resolve) => {
    if (output.writableNeedDrain) {
      output.once('drain', (): void => {
        endStreams(input, output, resolve);
      });
    } else {
      endStreams(input, output, resolve);
    }
  });
};

const numberTo4ByteBuffer = (num: number): Buffer => {
  const buffer = Buffer.alloc(4);
  buffer.writeUint32BE(num);
  return buffer;
};

const encryptFilename = async (filename: string, key: Buffer, id: string, output: Writable): Promise<string> => {
  const data = Buffer.from(filename, 'utf8');
  const nonce = aesNonceGen();
  const additionalData = Buffer.from(id, 'utf8');
  const [ciphertext, authTag] = aesgcmEncrypt(data, key, nonce, additionalData);
  await writeBufferToOutputWhenReady(Buffer.concat([nonce, authTag]), output);
  return ciphertext.toString('base64url');
};

const encryptHeader = async (
  contentKey: Buffer,
  superKey: Buffer,
  filesize: number,
  encryptedFilename: string,
  output: Writable
): Promise<void> => {
  const chunks = Math.ceil(filesize / chunkSize);
  const header = Buffer.concat([Buffer.from('FF'.repeat(8), 'hex'), contentKey]);
  const nonce = aesNonceGen();
  const additionalData = Buffer.concat([Buffer.from(encryptedFilename, 'base64url'), numberTo4ByteBuffer(chunks)]);
  const [ciphertext, authTag] = aesgcmEncrypt(header, superKey, nonce, additionalData);
  await writeBufferToOutputWhenReady(Buffer.concat([nonce, ciphertext, authTag]), output);
};

const readNextPlaintextChunk = (input: Readable, pos: number, filesize: number): Promise<Buffer> => {
  const chunkParts: Buffer[] = [];
  const sizeToRetrieve = Math.min(filesize - pos, chunkSize);
  let retrievedSize = 0;

  return new Promise((resolve) => {
    input.on('readable', (): void => {
      const chunkPart = input.read(sizeToRetrieve - retrievedSize);
      if (!chunkPart) return;
      chunkParts.push(chunkPart);
      retrievedSize += chunkPart.length;
      if (retrievedSize === sizeToRetrieve) {
        input.removeAllListeners('readable');
        resolve(chunkParts.length === 1 ? chunkParts[0] : Buffer.concat(chunkParts));
      }
    });
    if (input.readable) {
      input.emit('readable');
    }
  });
};

const encryptChunk = (chunk: Buffer, key: Buffer, encryptedFilename: string, index: number): Buffer => {
  const nonce = aesNonceGen();
  const additionalData = Buffer.concat([Buffer.from(encryptedFilename, 'base64url'), numberTo4ByteBuffer(index)]);
  const [ciphertext, authTag] = aesgcmEncrypt(chunk, key, nonce, additionalData);
  return Buffer.concat([nonce, ciphertext, authTag]);
};

const encryptPayload = async (
  input: Readable,
  output: Writable,
  key: Buffer,
  encryptedFilename: string,
  filesize: number
): Promise<void> => {
  let pos = 0;
  let index = 0;

  do {
    const chunk = await readNextPlaintextChunk(input, pos, filesize);
    const encryptedChunk = encryptChunk(chunk, key, encryptedFilename, index);
    await writeBufferToOutputWhenReady(encryptedChunk, output);
    index++;
    pos += chunk.length;
  } while (pos < filesize);

  await endStreamsWhenReady(input, output);
};

const encrypt = async (
  input: Readable,
  output: Writable,
  filename: string,
  filesize: number,
  key: Buffer,
  id: string,
  progressCallback?: ProgressCallback
): Promise<string> => {
  const headerSize = 68;
  const nonceAndAuthTagSize = 28;
  setProgressCallback(
    filesize + headerSize + nonceAndAuthTagSize + Math.ceil(filesize / chunkSize) * nonceAndAuthTagSize,
    progressCallback
  );
  setStreamsInfinityMaxListeners(input, output);

  const nameKey = aesKeyGen();
  const contentKey = aesKeyGen();
  const encryptedFilename = await encryptFilename(filename, nameKey, id, output);
  await encryptHeader(contentKey, key, filesize, encryptedFilename, output);
  await encryptPayload(input, output, contentKey, encryptedFilename, filesize);

  return encryptedFilename;
};

export { encrypt };
