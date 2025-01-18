const AES256GCM = require('../src/encryption/aes256gcm');

describe('AES256GCM Encryption', () => {
  let encryption;
  let userKeys;
  let notaryKeys;

  beforeEach(() => {
    encryption = new AES256GCM();
    userKeys = encryption.generateKeyPair();
    notaryKeys = encryption.generateKeyPair();
  });

  describe('Basic Encryption', () => {
    test('should generate valid key pair', () => {
      expect(userKeys).toHaveProperty('privateKey');
      expect(userKeys).toHaveProperty('publicKey');
      expect(typeof userKeys.privateKey).toBe('string');
      expect(typeof userKeys.publicKey).toBe('string');
    });

    test('should encrypt and decrypt string data correctly', async () => {
      const testData = 'Hello, World!';
      
      const encrypted = await encryption.encryptFor(testData, userKeys.publicKey);
      
      expect(encrypted).toHaveProperty('publicSignals');
      expect(encrypted.publicSignals).toHaveProperty('encryptedData');
      expect(encrypted.publicSignals).toHaveProperty('initVector');
      expect(encrypted.publicSignals).toHaveProperty('verificationTag');
      
      const decrypted = await encryption.decryptMine({
        publicSignals: encrypted.publicSignals,
        privateKey: userKeys.privateKey
      });
      
      expect(decrypted).toBe(testData);
    });

    test('should encrypt and decrypt object data correctly', async () => {
      const testData = { message: 'Hello', number: 42 };
      
      const encrypted = await encryption.encryptFor(testData, userKeys.publicKey);
      const decrypted = await encryption.decryptMine({
        publicSignals: encrypted.publicSignals,
        privateKey: userKeys.privateKey
      });
      
      expect(decrypted).toEqual(testData);
    });
  });

  describe('Notary Encryption', () => {
    test('should encrypt with notary access', async () => {
      const testData = { secret: 'sensitive data' };
      
      const encrypted = await encryption.encryptWithNotary(
        testData,
        userKeys.publicKey,
        notaryKeys.publicKey
      );

      // Check structure
      expect(encrypted).toHaveProperty('publicSignals');
      expect(encrypted.publicSignals).toHaveProperty('user');
      expect(encrypted.publicSignals).toHaveProperty('notary');
      expect(encrypted.publicSignals).toHaveProperty('initVector');
    });

    test('both user and notary should be able to decrypt', async () => {
      const testData = { amount: 1000 };
      
      const encrypted = await encryption.encryptWithNotary(
        testData,
        userKeys.publicKey,
        notaryKeys.publicKey
      );

      // User decryption
      const userDecrypted = await encryption.decrypt({
        publicSignals: encrypted.publicSignals,
        privateKey: userKeys.privateKey,
        type: 'user'
      });

      // Notary decryption
      const notaryDecrypted = await encryption.decrypt({
        publicSignals: encrypted.publicSignals,
        privateKey: notaryKeys.privateKey,
        type: 'notary'
      });

      expect(userDecrypted).toEqual(testData);
      expect(notaryDecrypted).toEqual(testData);
    });

    test('should fail with wrong private keys', async () => {
      const testData = { secret: 'data' };
      
      const encrypted = await encryption.encryptWithNotary(
        testData,
        userKeys.publicKey,
        notaryKeys.publicKey
      );

      // Try to decrypt with wrong keys
      await expect(encryption.decrypt({
        publicSignals: encrypted.publicSignals,
        privateKey: 'wrong-key',
        type: 'user'
      })).rejects.toThrow('Decryption failed');

      await expect(encryption.decrypt({
        publicSignals: encrypted.publicSignals,
        privateKey: 'wrong-key',
        type: 'notary'
      })).rejects.toThrow('Decryption failed');
    });
  });

  test('should batch decrypt multiple messages', async () => {
    const messages = ['Message 1', 'Message 2', 'Message 3'];
    
    const encrypted = await Promise.all(
      messages.map(msg => encryption.encryptFor(msg, userKeys.publicKey))
    );

    const decrypted = await encryption.decryptMyMany(
      encrypted.map(e => e.publicSignals),
      userKeys.privateKey
    );

    expect(decrypted).toEqual(messages);
  });
}); 