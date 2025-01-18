const Secp256k1E2E = require('../src/encryption/secp256k1E2E');
const ethers = require('ethers');

describe('Secp256k1E2E', () => {
  let encryption;
  let wallet;
  let recipientAddress;
  let recipientPublicKey;
  let testData;

  beforeEach(async () => {
    encryption = new Secp256k1E2E();
    wallet = ethers.Wallet.createRandom();
    recipientAddress = wallet.address;
    recipientPublicKey = Buffer.from(wallet.publicKey.slice(2), 'hex');
    testData = { secret: 'test123' };
  });

  describe('Basic Encryption', () => {
    test('should encrypt and decrypt string data correctly', async () => {
      const testString = 'Hello, World!';
      
      const encrypted = await encryption.encryptFor(testString, recipientAddress, recipientPublicKey);
      
      expect(encrypted).toHaveProperty('publicSignals');
      expect(encrypted.publicSignals).toHaveProperty('encryptedData');
      expect(encrypted.publicSignals).toHaveProperty('initVector');
      expect(encrypted.publicSignals).toHaveProperty('verificationTag');
      expect(encrypted.publicSignals).toHaveProperty('ephemeralPublicKey');
      
      const decrypted = await encryption.decrypt({
        publicSignals: encrypted.publicSignals,
        privateKey: wallet.privateKey
      });
      
      expect(decrypted).toBe(testString);
    });

    test('should encrypt and decrypt object data correctly', async () => {
      const encrypted = await encryption.encryptFor(testData, recipientAddress, recipientPublicKey);
      const decrypted = await encryption.decrypt({
        publicSignals: encrypted.publicSignals,
        privateKey: wallet.privateKey
      });
      
      expect(decrypted).toEqual(testData);
    });

    test('should fail with tampered data', async () => {
      const encrypted = await encryption.encryptFor(testData, recipientAddress, recipientPublicKey);
      
      // Tamper with encrypted data
      encrypted.publicSignals.encryptedData = 
        encrypted.publicSignals.encryptedData.replace('a', 'b');

      await expect(
        encryption.decrypt({
          publicSignals: encrypted.publicSignals,
          privateKey: wallet.privateKey
        })
      ).rejects.toThrow('Data integrity check failed');
    });
  });

  describe('Notary Encryption', () => {
    let notaryWallet;
    let notaryPublicKey;

    beforeEach(() => {
      notaryWallet = ethers.Wallet.createRandom();
      notaryPublicKey = Buffer.from(notaryWallet.publicKey.slice(2), 'hex');
    });

    test('should encrypt with notary access', async () => {
      const encrypted = await encryption.encryptWithNotary(
        testData,
        recipientAddress,
        recipientPublicKey,
        notaryWallet.address,
        notaryPublicKey
      );

      expect(encrypted).toHaveProperty('publicSignals');
      expect(encrypted.publicSignals).toHaveProperty('user');
      expect(encrypted.publicSignals).toHaveProperty('notary');
    });

    test('both user and notary should be able to decrypt', async () => {
      const encrypted = await encryption.encryptWithNotary(
        testData,
        recipientAddress,
        recipientPublicKey,
        notaryWallet.address,
        notaryPublicKey
      );

      // User decryption
      const userDecrypted = await encryption.decrypt({
        publicSignals: encrypted.publicSignals,
        privateKey: wallet.privateKey,
        type: 'user'
      });

      // Notary decryption
      const notaryDecrypted = await encryption.decrypt({
        publicSignals: encrypted.publicSignals,
        privateKey: notaryWallet.privateKey,
        type: 'notary'
      });

      expect(userDecrypted).toEqual(testData);
      expect(notaryDecrypted).toEqual(testData);
    });
  });

  describe('Error Handling', () => {
    test('should reject invalid addresses', async () => {
      await expect(
        encryption.encryptFor(testData, 'invalid-address', recipientPublicKey)
      ).rejects.toThrow('Invalid recipient address');
    });

    test('should reject missing required fields', async () => {
      const encrypted = await encryption.encryptFor(testData, recipientAddress, recipientPublicKey);
      delete encrypted.publicSignals.verificationTag;

      await expect(
        encryption.decrypt({
          publicSignals: encrypted.publicSignals,
          privateKey: wallet.privateKey
        })
      ).rejects.toThrow('Missing required field');
    });

    test('should fail with wrong private key', async () => {
      const encrypted = await encryption.encryptFor(testData, recipientAddress, recipientPublicKey);
      const wrongWallet = ethers.Wallet.createRandom();

      await expect(
        encryption.decrypt({
          publicSignals: encrypted.publicSignals,
          privateKey: wrongWallet.privateKey
        })
      ).rejects.toThrow('Decryption failed');
    });
  });

  test('should batch decrypt multiple messages', async () => {
    const messages = ['Message 1', 'Message 2', 'Message 3'];
    
    const encrypted = await Promise.all(
      messages.map(msg => encryption.encryptFor(msg, recipientAddress, recipientPublicKey))
    );

    const decrypted = await encryption.decryptMyMany(
      encrypted.map(e => e.publicSignals),
      wallet.privateKey
    );

    expect(decrypted).toEqual(messages);
  });

  test('should handle different data types correctly', async () => {
    const testCases = [
      null,
      undefined,
      123,
      'string',
      { obj: 'test' },
      [1, 2, 3]
    ];

    for (const testCase of testCases) {
      const encrypted = await encryption.encryptFor(testCase, recipientAddress, recipientPublicKey);
      const decrypted = await encryption.decrypt({
        publicSignals: encrypted.publicSignals,
        privateKey: wallet.privateKey
      });

      expect(decrypted).toEqual(testCase);
    }
  });
}); 