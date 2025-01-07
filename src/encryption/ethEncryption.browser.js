// Browser version - using ES modules
export class ETHEncryption {
    constructor() {
        if (!window.secp256k1) {
            throw new Error('Required secp256k1 not found');
        }
        this.secp = window.secp256k1;
        this.algorithm = 'AES-GCM';
    }

    async encryptFor(data, recipientAddress) {
        if (!recipientAddress || !ethers.utils.isAddress(recipientAddress)) {
            throw new Error('Invalid recipient address');
        }

        // Generate ephemeral key pair using noble-secp256k1
        const ephemeralPrivateKey = this.secp.utils.randomPrivateKey();
        const ephemeralPublicKey = this.secp.getPublicKey(ephemeralPrivateKey);

        // Get recipient's public key
        const recipientPublicKey = await this.getPublicKey(recipientAddress);

        // Generate shared secret using noble-secp256k1
        const sharedSecret = this.secp.getSharedSecret(
            ephemeralPrivateKey,
            recipientPublicKey
        );

        // Use Web Crypto API instead of Node's crypto
        const encryptionKey = await crypto.subtle.importKey(
            'raw',
            sharedSecret.slice(0, 32),
            { name: this.algorithm },
            false,
            ['encrypt']
        );

        const iv = crypto.getRandomValues(new Uint8Array(12));
        const stringData = this._normalizeData(data);
        const encodedData = new TextEncoder().encode(stringData);
        const associatedData = new TextEncoder().encode(recipientAddress.toLowerCase());

        const encrypted = await crypto.subtle.encrypt(
            {
                name: this.algorithm,
                iv: iv,
                additionalData: associatedData
            },
            encryptionKey,
            encodedData
        );

        // Get the last 16 bytes as verification tag (like Node's authTag)
        const encryptedArray = new Uint8Array(encrypted);
        const verificationTag = encryptedArray.slice(-16);
        const encryptedData = encryptedArray.slice(0, -16);

        return {
            publicSignals: {
                encryptedData: this._arrayBufferToHex(encryptedData),
                initVector: this._arrayBufferToHex(iv),
                verificationTag: this._arrayBufferToHex(verificationTag),
                ephemeralPublicKey: this._arrayBufferToHex(ephemeralPublicKey),
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

        this._validateSignals(signals);

        try {
            const privateKeyBytes = this._validateAndFormatPrivateKey(privateKey);
            const ephemeralPubKey = this._hexToBytes(signals.ephemeralPublicKey);

            if (ephemeralPubKey.length !== 33 && ephemeralPubKey.length !== 65) {
                throw new Error('Invalid ephemeral public key length');
            }

            const sharedSecret = this.secp.getSharedSecret(
                privateKeyBytes,
                ephemeralPubKey,
                { recovered: true }
            );

            const decryptionKey = await crypto.subtle.importKey(
                'raw',
                sharedSecret.slice(0, 32),
                { name: this.algorithm },
                false,
                ['decrypt']
            );

            // Combine encrypted data and verification tag
            const encryptedData = this._hexToBytes(signals.encryptedData);
            const verificationTag = this._hexToBytes(signals.verificationTag);
            const combinedData = new Uint8Array([...encryptedData, ...verificationTag]);

            const decrypted = await crypto.subtle.decrypt(
                {
                    name: this.algorithm,
                    iv: this._hexToBytes(signals.initVector),
                    additionalData: new TextEncoder().encode(signals.forAddress.toLowerCase())
                },
                decryptionKey,
                combinedData
            );

            return this._denormalizeData(new TextDecoder().decode(decrypted));
        } catch (error) {
            console.error('Detailed error:', error);
            throw new Error(`Decryption failed: ${error.message}`);
        }
    }

    // Helper methods
    _arrayBufferToHex(buffer) {
        return Array.from(new Uint8Array(buffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    _hexToBytes(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
        }
        return bytes;
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

    // For testing, return a dummy public key
    async getPublicKey(address) {
        const privateKey = this.secp.utils.randomPrivateKey();
        const publicKey = this.secp.getPublicKey(privateKey, true);
        return publicKey;
    }

    // Add Node.js version validation methods
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

        const privateKeyBytes = this._hexToBytes(privateKey.slice(2));
        
        if (privateKeyBytes.length !== 32) {
            throw new Error('Invalid private key length');
        }

        return privateKeyBytes;
    }
} 
