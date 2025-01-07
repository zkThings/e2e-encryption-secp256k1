const crypto = require('crypto');
const Encryption = require('./base');

class AES256GCM extends Encryption {
  constructor() {
    super();
    this.algorithm = 'aes-256-gcm';
  }

  generateKeyPair() {
    const privateKey = crypto.randomBytes(32).toString('hex');
    const publicKey = crypto
      .createHash('sha256')
      .update(privateKey)
      .digest('hex');

    return {
      privateKey,
      publicKey
    };
  }

  // Encrypt with dual access (both user and notary can decrypt)
  async encryptWithNotary(data, userPublicKey, notaryPublicKey) {
    const iv = crypto.randomBytes(16);
    
    // Encrypt for user
    const userEncryption = await this.encryptFor(data, userPublicKey);
    
    // Encrypt same data for notary
    const notaryEncryption = await this.encryptFor(data, notaryPublicKey);

    return {
      publicSignals: {
        user: userEncryption.publicSignals,
        notary: notaryEncryption.publicSignals,
        initVector: iv.toString('hex')
      }
    };
  }

  // Now both user and notary can decrypt
  async decrypt({ publicSignals, privateKey, type = 'user' }) {
    const signals = type === 'user' ? 
      publicSignals.user : 
      publicSignals.notary;

    return this.decryptMine({
      publicSignals: signals,
      privateKey
    });
  }

  async encryptFor(data, recipientPublicKey) {
    const iv = crypto.randomBytes(16);
    
    // Use the first 32 bytes of public key for encryption
    const encryptionKey = Buffer.from(recipientPublicKey.slice(0, 64), 'hex');
    
    const cipher = crypto.createCipheriv(
      this.algorithm, 
      encryptionKey,
      iv
    );
    
    const stringData = typeof data === 'object' ? JSON.stringify(data) : data;
    let encrypted = cipher.update(stringData, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();

    return {
      publicSignals: {
        encryptedData: encrypted,
        initVector: iv.toString('hex'),
        verificationTag: authTag.toString('hex')
      }
    };
  }

  async decryptMine({ publicSignals, privateKey }) {
    try {
      // Use the first 32 bytes of derived public key for decryption
      const decryptionKey = crypto
        .createHash('sha256')
        .update(privateKey)
        .digest()
        .slice(0, 32);

      const decipher = crypto.createDecipheriv(
        this.algorithm,
        decryptionKey,
        Buffer.from(publicSignals.initVector, 'hex')
      );
      
      console.log(publicSignals);
      
      decipher.setAuthTag(Buffer.from(publicSignals.verificationTag, 'hex'));
      
      let decrypted = decipher.update(publicSignals.encryptedData, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      try {
        return JSON.parse(decrypted);
      } catch {
        return decrypted;
      }
    } catch (error) {
      throw new Error('Decryption failed: Invalid decryption key or tampered data');
    }
  }

  // Add the missing decryptMyMany method
  async decryptMyMany(encryptedItems, privateKey) {
    return Promise.all(
      encryptedItems.map(item => 
        this.decryptMine({
          publicSignals: item,
          privateKey
        })
      )
    );
  }
}

module.exports = AES256GCM; 