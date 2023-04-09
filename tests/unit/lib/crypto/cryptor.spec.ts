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
  'DAwMDAwMDAwMDAwM9zxtT/ILrh+KxXr9vc7dhQwMDAwMDAwMDAwMDJDXtYEukZAAYIUJPVaMdkPlU4eWBW8/MdBYtRyFgo8xrDt0FiXiYsjGCd0FAZh025he0S5SkoZrDAwMDAwMDAwMDAwMbyhKftFub/9ApSkddqxWY8Vzp7YlTx8R8HiVPKWirxGMG1Q2BcJC6MQUrJOcK1n+yoxhEN7LpMH9REoKouJ9K4+TKWFjyHh+/YklAanZaRcMDAwMDAwMDAwMDAxvKEp+0W5v/0ClKR12rFZjxXOntiVPHxHweJU8paKvEaR6kpwDTezdZ3mxZrSRpds=',
  'base64'
);
const id = 'id';
const filename = 'test';
const encryptedFilename = 'G005Cg';

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
    const expectedProgressLog = [0, 11, 39, 76, 100];
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
