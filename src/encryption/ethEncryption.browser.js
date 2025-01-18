const secp256k1 = require('secp256k1');
const crypto = require('crypto');
const ethers = require('ethers');

class ETHEncryption {
    constructor() {
        this.algorithm = 'aes-256-gcm';
    }

    async encryptFor(data, recipientAddress, recipientPublicKey) {
        try {
            // Validate address format using ethers
            recipientAddress = recipientAddress?.toLowerCase();
            if (!recipientAddress || !ethers.isAddress(recipientAddress)) {
                throw new Error('Invalid recipient address');
            }

            // Handle public key input - use only Uint8Array
            let pubKeyUint8;
            if (recipientPublicKey instanceof Uint8Array) {
                pubKeyUint8 = recipientPublicKey;
            } else if (Array.isArray(recipientPublicKey) || ArrayBuffer.isView(recipientPublicKey)) {
                pubKeyUint8 = new Uint8Array(recipientPublicKey);
            } else {
                throw new Error('Invalid public key format');
            }

            // Validate the public key using secp256k1
            if (!secp256k1.publicKeyVerify(pubKeyUint8)) {
                throw new Error('Invalid recipient public key');
            }

            // Generate ephemeral key pair using crypto.getRandomValues
            const ephemeralPrivateKey = new Uint8Array(32);
            crypto.getRandomValues(ephemeralPrivateKey);
            while (!secp256k1.privateKeyVerify(ephemeralPrivateKey)) {
                crypto.getRandomValues(ephemeralPrivateKey);
            }

            const ephemeralPublicKey = secp256k1.publicKeyCreate(new Uint8Array(ephemeralPrivateKey));

            // Generate shared secret using ECDH
            const sharedSecret = secp256k1.ecdh(
                pubKeyUint8,
                new Uint8Array(ephemeralPrivateKey)
            );

            // Generate encryption key using HKDF
            const encryptionKey = crypto.createHmac('sha256', sharedSecret)
                .update('ENCRYPTION_KEY')
                .digest();

            const iv = crypto.randomBytes(12);
            const cipher = crypto.createCipheriv(this.algorithm, encryptionKey, iv);
            
            // Add associated data for authentication
            const associatedData = Buffer.from(recipientAddress.toLowerCase());
            cipher.setAAD(associatedData);
            
            const stringData = this._normalizeData(data);
            let encryptedData = cipher.update(stringData, 'utf8', 'hex');
            encryptedData += cipher.final('hex');
            
            const verificationTag = cipher.getAuthTag();

            // Return direct properties (not nested under publicSignals)
            return {
                encryptedData,
                initVector: iv.toString('hex'),
                verificationTag: verificationTag.toString('hex'),
                ephemeralPublicKey: Buffer.from(ephemeralPublicKey).toString('hex'),
                forAddress: recipientAddress.toLowerCase(),
                communityId: recipientAddress.toLowerCase(),
                version: '1.0'
            };

        } catch (error) {
            console.error('Encryption error:', error);
            throw error;
        }
    }

    _normalizeData(data) {
        if (data === null) return 'null';
        if (data === undefined) return 'undefined';
        return typeof data === 'object' ? JSON.stringify(data) : String(data);
    }

    async decrypt(encryptedData, privateKey) {
        try {
            // Remove '0x' prefix if present
            privateKey = privateKey.replace('0x', '');
            
            // Convert hex private key to Uint8Array
            const privateKeyBytes = new Uint8Array(
                privateKey.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
            );

            // Convert hex strings back to buffers
            const iv = new Uint8Array(
                encryptedData.initVector.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
            );
            
            const ephemeralPublicKey = new Uint8Array(
                encryptedData.ephemeralPublicKey.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
            );
            
            const verificationTag = new Uint8Array(
                encryptedData.verificationTag.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
            );

            // Generate shared secret using ECDH
            const sharedSecret = secp256k1.ecdh(
                ephemeralPublicKey,
                privateKeyBytes
            );

            // Generate decryption key using HKDF
            const decryptionKey = crypto.createHmac('sha256', sharedSecret)
                .update('ENCRYPTION_KEY')
                .digest();

            // Create decipher
            const decipher = crypto.createDecipheriv(this.algorithm, decryptionKey, iv);
            
            // Add associated data for authentication
            const associatedData = Buffer.from(encryptedData.communityId.toLowerCase());
            decipher.setAAD(associatedData);
            
            // Set auth tag
            decipher.setAuthTag(verificationTag);

            // Decrypt
            let decrypted = decipher.update(encryptedData.encryptedData, 'hex', 'utf8');
            decrypted += decipher.final('utf8');

            // Parse the decrypted data
            try {
                return JSON.parse(decrypted);
            } catch {
                return decrypted === 'undefined' ? undefined :
                       decrypted === 'null' ? null :
                       decrypted;
            }
        } catch (error) {
            console.error('Decryption error:', error);
            throw error;
        }
    }
}

module.exports = ETHEncryption; 
