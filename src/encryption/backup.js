const ethers = require('ethers');
const crypto = require('crypto');
const secp256k1 = require('secp256k1');
const Encryption = require('./base');

class ETHEncryption extends Encryption {
  constructor() {
    super();
    this.algorithm = 'aes-256-gcm';
  }

  async encryptFor(data, recipientAddress) {
    if (!recipientAddress) {
      throw new Error('Missing recipient address');
    }

    // New random key for each encryption
    let ephemeralPrivateKey = crypto.randomBytes(32);

    const ephemeralPublicKey = secp256k1.publicKeyCreate(ephemeralPrivateKey);

    // Get recipient's public key from their address
    // In real implementation, this would need to be provided or looked up
    const recipientPublicKey = await this.getPublicKey(recipientAddress);

    // Generate shared secret using ECDH
    // Only the holder of recipient's private key can recreate this
    const sharedSecret = secp256k1.ecdh(
      recipientPublicKey,
      ephemeralPrivateKey
    );

    // Generate encryption key from shared secret
    const encryptionKey = crypto.createHash('sha256')
      .update(sharedSecret)
      .digest();

    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(this.algorithm, encryptionKey, iv);
    
    const stringData = data === null ? 'null' : 
                      data === undefined ? 'undefined' : 
                      typeof data === 'object' ? JSON.stringify(data) : 
                      String(data);
    
    let encrypted = cipher.update(stringData, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();

    return {
      publicSignals: {
        encryptedData: encrypted,
        initVector: iv.toString('hex'),
        verificationTag: authTag.toString('hex'),
        ephemeralPublicKey: Buffer.from(ephemeralPublicKey).toString('hex'),
        forAddress: recipientAddress
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

    try {
      // Convert private key to proper format
      const privateKeyBuffer = Buffer.from(privateKey.slice(2), 'hex');
      
      // Recreate shared secret using recipient's private key
      const sharedSecret = secp256k1.ecdh(
        Buffer.from(signals.ephemeralPublicKey, 'hex'),
        privateKeyBuffer
      );

      // Derive the same encryption key
      const decryptionKey = crypto.createHash('sha256')
        .update(sharedSecret)
        .digest();
      
      const decipher = crypto.createDecipheriv(
        this.algorithm,
        decryptionKey,
        Buffer.from(signals.initVector, 'hex')
      );
      
      decipher.setAuthTag(Buffer.from(signals.verificationTag, 'hex'));
      
      let decrypted = decipher.update(signals.encryptedData, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      if (decrypted === 'null') return null;
      if (decrypted === 'undefined') return undefined;
      
      try {
        return JSON.parse(decrypted);
      } catch {
        return decrypted;
      }
    } catch (error) {
      throw new Error('Decryption failed');
    }
  }

  async encryptWithNotary(data, userAddress, notaryAddress) {
    const userEncryption = await this.encryptFor(data, userAddress);
    const notaryEncryption = await this.encryptFor(data, notaryAddress);

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

  // This would need to be implemented to get public key from address
  async getPublicKey(address) {
    // In real implementation, this would:
    // 1. Look up public key from a registry
    // 2. Or require it to be passed in
    // 3. Or recover it from a signature
    throw new Error('Public key retrieval not implemented');
  }
}

module.exports = ETHEncryption; 