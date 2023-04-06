import { Readable, Writable } from 'stream';
import { chunkSize } from './properties';
import { aesgcmEncrypt, aesKeyGen, aesNonceGen } from './aesgcm';

const numberTo4ByteBuffer = (num: number): Buffer => {
  const buffer = Buffer.alloc(4);
  buffer.writeUint32BE(num);
  return buffer;
};

const writeBufferToOutput = (buffer: Buffer, output: Writable): Promise<void> => {
  return new Promise((resolve, reject) => {
    output.write(buffer, (error) => {
      if (error) reject(error);
      else resolve();
    });
  });
};

const endOutput = (output: Writable): Promise<void> => {
  return new Promise((resolve) => {
    output.end((): void => {
      resolve();
    });
  });
};

const encryptFilename = (filename: string, key: Buffer, id: string): string => {
  const data = Buffer.from(filename, 'utf8');
  const nonce = aesNonceGen();
  const additionalData = Buffer.from(id, 'utf8');
  const encryptedFilename = aesgcmEncrypt(data, key, nonce, additionalData);
  return Buffer.concat([nonce, encryptedFilename]).toString('base64url');
};

const encryptHeader = (contentKey: Buffer, superKey: Buffer, filesize: number, encryptedFilename: string): Buffer => {
  const chunks = Math.ceil(filesize / chunkSize);
  const header = Buffer.concat([Buffer.from('FF'.repeat(8), 'hex'), contentKey]);
  const nonce = aesNonceGen();
  const additionalData = Buffer.concat([Buffer.from(encryptedFilename, 'base64url'), numberTo4ByteBuffer(chunks)]);
  const encryptedHeader = aesgcmEncrypt(header, superKey, nonce, additionalData);
  return Buffer.concat([nonce, encryptedHeader]);
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
  const encryptedchunk = aesgcmEncrypt(chunk, key, nonce, additionalData);
  return Buffer.concat([nonce, encryptedchunk]);
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
    await writeBufferToOutput(encryptedChunk, output);
    index++;
    pos += chunk.length;
  } while (pos < filesize);

  await endOutput(output);
};

const encrypt = async (
  input: Readable,
  output: Writable,
  filename: string,
  filesize: number,
  key: Buffer,
  id: string
): Promise<string> => {
  const nameKey = aesKeyGen();
  const contentKey = aesKeyGen();
  const encryptedFilename = encryptFilename(filename, nameKey, id);

  const encryptedHeader = encryptHeader(contentKey, key, filesize, encryptedFilename);
  await writeBufferToOutput(encryptedHeader, output);

  await encryptPayload(input, output, contentKey, encryptedFilename, filesize);

  return encryptedFilename;
};

export { encrypt };