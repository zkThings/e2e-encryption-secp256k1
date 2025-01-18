const ethers = require('ethers');
const crypto = require('crypto');
const secp256k1 = require('secp256k1');
const BaseE2E = require('./base');

class Secp256k1E2E extends BaseE2E {
  constructor() {
    super();
    this.algorithm = 'aes-256-gcm';
  }

  async encryptFor(data, recipientAddress, recipientPublicKey) {
    if (!recipientAddress || !ethers.isAddress(recipientAddress)) {
      throw new Error('Invalid recipient address');
    }

    // Try registry if public key not provided
    if (!recipientPublicKey) {
      recipientPublicKey = await this.getPublicKeyFromRegistry(recipientAddress);
    }

    // Validate public key
    if (!recipientPublicKey || !secp256k1.publicKeyVerify(recipientPublicKey)) {
      throw new Error('Invalid recipient public key');
    }

    // Generate ephemeral key pair with verification
    let ephemeralPrivateKey;
    do {
      ephemeralPrivateKey = crypto.randomBytes(32);
    } while (!secp256k1.privateKeyVerify(ephemeralPrivateKey));

    const ephemeralPublicKey = secp256k1.publicKeyCreate(ephemeralPrivateKey);

    // Generate shared secret using ECDH
    const sharedSecret = secp256k1.ecdh(recipientPublicKey, ephemeralPrivateKey);

    // Generate encryption key using HKDF
    const encryptionKey = crypto.createHmac('sha256', sharedSecret)
      .update('ENCRYPTION_KEY')
      .digest();

    const iv = crypto.randomBytes(12); // 96 bits for GCM
    const cipher = crypto.createCipheriv(this.algorithm, encryptionKey, iv);
    
    // Standardize data format
    const stringData = this._normalizeData(data);
    
    // Add associated data for additional security
    const associatedData = Buffer.from(recipientAddress.toLowerCase());
    cipher.setAAD(associatedData);

    let encrypted = cipher.update(stringData, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();

    return {
      publicSignals: {
        encryptedData: encrypted,
        initVector: iv.toString('hex'),
        verificationTag: authTag.toString('hex'),
        ephemeralPublicKey: Buffer.from(ephemeralPublicKey).toString('hex'),
        forAddress: recipientAddress.toLowerCase(),
        version: '1.0'
      }
    };
  }

  async decrypt({ publicSignals, privateKey, type = 'user' }) {
    if (!publicSignals || !privateKey) {
      throw new Error('Missing required parameters');
    }

    const signals = type === 'user' ? 
      publicSignals.user || publicSignals : 
      publicSignals.notary;

    // Validate all required fields
    this._validateSignals(signals);

    try {
      const privateKeyBuffer = this._validateAndFormatPrivateKey(privateKey);
      
      // Validate ephemeral public key
      const ephemeralPubKey = Buffer.from(signals.ephemeralPublicKey, 'hex');
      if (!secp256k1.publicKeyVerify(ephemeralPubKey)) {
        throw new Error('Invalid ephemeral public key');
      }

      const sharedSecret = secp256k1.ecdh(ephemeralPubKey, privateKeyBuffer);
      
      // Derive decryption key using HKDF
      const decryptionKey = crypto.createHmac('sha256', sharedSecret)
        .update('ENCRYPTION_KEY')
        .digest();

      const decipher = crypto.createDecipheriv(
        this.algorithm,
        decryptionKey,
        Buffer.from(signals.initVector, 'hex')
      );

      // Add associated data for verification
      const associatedData = Buffer.from(signals.forAddress.toLowerCase());
      decipher.setAAD(associatedData);
      
      decipher.setAuthTag(Buffer.from(signals.verificationTag, 'hex'));

      try {
        let decrypted = decipher.update(signals.encryptedData, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return this._denormalizeData(decrypted);
      } catch (error) {
        throw new Error('Data integrity check failed - possible tampering detected');
      }
    } catch (error) {
      throw new Error(`Decryption failed: ${error.message}`);
    }
  }

  _normalizeData(data) {
    if (data === null) return 'null';
    if (data === undefined) return 'undefined';
    return typeof data === 'object' ? JSON.stringify(data) : String(data);
  }

  _denormalizeData(data) {
    if (data === 'null') return null;
    if (data === 'undefined') return undefined;
    try {
      return JSON.parse(data);
    } catch {
      return data;
    }
  }

  _validateSignals(signals) {
    const requiredFields = [
      'encryptedData',
      'initVector',
      'verificationTag',
      'ephemeralPublicKey',
      'forAddress'
    ];

    for (const field of requiredFields) {
      if (!signals[field]) {
        throw new Error(`Missing required field: ${field}`);
      }
    }
  }

  _validateAndFormatPrivateKey(privateKey) {
    if (typeof privateKey !== 'string' || !privateKey.startsWith('0x')) {
      throw new Error('Invalid private key format');
    }

    const privateKeyBuffer = Buffer.from(privateKey.slice(2), 'hex');
    if (!secp256k1.privateKeyVerify(privateKeyBuffer)) {
      throw new Error('Invalid private key');
    }

    return privateKeyBuffer;
  }

  async encryptWithNotary(data, userAddress, userPublicKey, notaryAddress, notaryPublicKey) {
    const userEncryption = await this.encryptFor(data, userAddress, userPublicKey);
    const notaryEncryption = await this.encryptFor(data, notaryAddress, notaryPublicKey);

    return {
      publicSignals: {
        user: userEncryption.publicSignals,
        notary: notaryEncryption.publicSignals
      }
    };
  }

  async decryptMyMany(encryptedItems, privateKey) {
    return Promise.all(
      encryptedItems.map(item => 
        this.decrypt({
          publicSignals: item,
          privateKey
        })
      )
    );
  }

  async getPublicKeyFromRegistry(address) {
    // Placeholder for registry integration
    throw new Error('Please provide recipient public key or implement registry integration');
  }
}

module.exports = Secp256k1E2E; 