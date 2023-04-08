import { encrypt } from '@/lib/crypto/cryptor';
import { assert } from 'assertthat';
import fs from 'fs';

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

jest.mock('@/lib/crypto/properties', () => {
  const originalModule = jest.requireActual('@/lib/crypto/properties');

  return { ...originalModule, chunkSize: 64 };
});

const dataLength = 96;

const key = Buffer.from(new Uint8Array(32).fill(32));
const data = Buffer.from(new Uint8Array(dataLength));
const encrypted = Buffer.from(
  'DAwMDAwMDAwMDAwMkNe1gS6RkABghQk9Vox2Q+VTh5YFbz8x0Fi1HIWCjzGsO3QWJeJiyHg1bXUGgbGXvjYpEk8jylcMDAwMDAwMDAwMDAxvKEp+0W5v/0ClKR12rFZjxXOntiVPHxHweJU8paKvEYwbVDYFwkLoxBSsk5wrWf7KjGEQ3sukwf1ESgqi4n0r1z+b+2MV8LNwdT5yKZ77EwwMDAwMDAwMDAwMDG8oSn7Rbm//QKUpHXasVmPFc6e2JU8fEfB4lTyloq8RaJd2SjR7UCNbu8MKIEUkQw==',
  'base64'
);
const id = 'id';
const filename = 'test';
const encryptedFilename = 'DAwMDAwMDAwMDAwMG005Cvc8bU_yC64fisV6_b3O3YU';

const testFilepathData = './data';
const testFilepathEncrypted = './encrypted';

afterEach((): void => {
  for (const path of [testFilepathData, testFilepathEncrypted]) {
    if (fs.existsSync(path)) {
      fs.unlinkSync(path);
    }
  }
});

describe('Cryptor', (): void => {
  test('encrypts correctly, using test vector.', async (): Promise<void> => {
    const progressLog: number[] = [];
    const expectedProgressLog = [0, 31, 73, 100];
    const progressCallback = (percent: number): void => {
      progressLog.push(Math.round(percent));
    };
    fs.writeFileSync(testFilepathData, data);
    fs.writeFileSync(testFilepathEncrypted, Buffer.alloc(0));
    const input = fs.createReadStream(testFilepathData);
    const output = fs.createWriteStream(testFilepathEncrypted);

    const actualEncryptedFilename = await encrypt(input, output, filename, dataLength, key, id, progressCallback);

    assert.that(fs.readFileSync(testFilepathEncrypted)).is.equalTo(encrypted);
    assert.that(actualEncryptedFilename).is.equalTo(encryptedFilename);
    assert.that(progressLog).is.equalTo(expectedProgressLog);
  });
});
