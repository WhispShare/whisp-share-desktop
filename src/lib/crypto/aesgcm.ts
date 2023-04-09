import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

const algorithm = 'aes-256-gcm';

const aesKeyGen = () => randomBytes(32);

const aesNonceGen = () => randomBytes(12);

const aesgcmEncrypt = (data: Buffer, key: Buffer, nonce: Buffer, additionalData: Buffer): Buffer[] => {
  const cipher = createCipheriv(algorithm, key, nonce);
  cipher.setAAD(additionalData);
  const ciphertext = cipher.update(data);
  cipher.final();
  const authTag = cipher.getAuthTag();
  return [ciphertext, authTag];
};

const aesgcmDecrypt = (
  ciphertext: Buffer,
  authTag: Buffer,
  key: Buffer,
  nonce: Buffer,
  additionalData: Buffer
): Buffer => {
  const decipher = createDecipheriv(algorithm, key, nonce);
  decipher.setAAD(additionalData);
  decipher.setAuthTag(authTag);
  const data = decipher.update(ciphertext);
  decipher.final();
  return data;
};

export { aesgcmEncrypt, aesgcmDecrypt, aesKeyGen, aesNonceGen };
