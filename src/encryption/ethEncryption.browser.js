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

        // Generate ephemeral key pair - match Node.js version
        const ephemeralPrivateKey = this.secp.utils.randomPrivateKey();
        const ephemeralPublicKey = this.secp.getPublicKey(ephemeralPrivateKey, true); // Use compressed

        // Get recipient's public key
        const recipientPublicKey = await this.getPublicKey(recipientAddress);

        // Generate shared secret - match Node.js ECDH
        const sharedSecret = this.secp.getSharedSecret(
            ephemeralPrivateKey,
            recipientPublicKey
        );

        // Match Node.js HMAC key derivation
        const encryptionKey = await crypto.subtle.importKey(
            'raw',
            sharedSecret,
            { name: 'HMAC', hash: 'SHA-256' },
            true,
            ['sign']
        );
        
        const keyMaterial = await crypto.subtle.sign(
            'HMAC',
            encryptionKey,
            new TextEncoder().encode('ENCRYPTION_KEY')
        );

        // Import as AES key
        const aesKey = await crypto.subtle.importKey(
            'raw',
            keyMaterial.slice(0, 32),
            { name: this.algorithm },
            false,
            ['encrypt']
        );

        const iv = crypto.getRandomValues(new Uint8Array(12));
        const stringData = this._normalizeData(data);
        const encodedData = new TextEncoder().encode(stringData);

        const encrypted = await crypto.subtle.encrypt(
            {
                name: this.algorithm,
                iv: iv,
                additionalData: new TextEncoder().encode(recipientAddress.toLowerCase())
            },
            aesKey,
            encodedData
        );

        // Split encrypted data and auth tag to match Node.js format
        const encryptedBytes = new Uint8Array(encrypted);
        const authTag = encryptedBytes.slice(-16);
        const encryptedData = encryptedBytes.slice(0, -16);

        return {
            publicSignals: {
                encryptedData: this._arrayBufferToHex(encryptedData),
                initVector: this._arrayBufferToHex(iv),
                verificationTag: this._arrayBufferToHex(authTag),
                ephemeralPublicKey: this._arrayBufferToHex(ephemeralPublicKey),
                forAddress: recipientAddress.toLowerCase(),
                version: '1.0'
            }
        };
    }

    async decrypt({ publicSignals, privateKey }) {
        console.log('Starting decryption with:', { publicSignals, privateKey });

        try {
            // 1. Validate inputs
            this._validateSignals(publicSignals);
            const privateKeyBytes = this._validateAndFormatPrivateKey(privateKey);
            const ephemeralPubKey = this._hexToBytes(publicSignals.ephemeralPublicKey);

            // 2. Generate shared secret
            const sharedSecret = this.secp.getSharedSecret(
                privateKeyBytes,
                ephemeralPubKey
            );

            // 3. Match encryption key derivation
            const encryptionKey = await crypto.subtle.importKey(
                'raw',
                sharedSecret,
                { name: 'HMAC', hash: 'SHA-256' },
                true,
                ['sign']
            );
            
            const keyMaterial = await crypto.subtle.sign(
                'HMAC',
                encryptionKey,
                new TextEncoder().encode('ENCRYPTION_KEY')
            );

            // 4. Import as AES key
            const aesKey = await crypto.subtle.importKey(
                'raw',
                keyMaterial.slice(0, 32),
                { name: this.algorithm },
                false,
                ['decrypt']
            );

            // 5. Prepare decryption parameters
            const iv = this._hexToBytes(publicSignals.initVector);
            const encryptedData = this._hexToBytes(publicSignals.encryptedData);
            const authTag = this._hexToBytes(publicSignals.verificationTag);

            // 6. Combine data for decryption
            const encryptedContent = new Uint8Array(encryptedData.length + authTag.length);
            encryptedContent.set(encryptedData);
            encryptedContent.set(authTag, encryptedData.length);

            // 7. Decrypt
            const decrypted = await window.crypto.subtle.decrypt(
                {
                    name: this.algorithm,
                    iv: iv,
                    additionalData: new TextEncoder().encode(publicSignals.forAddress.toLowerCase())
                },
                aesKey,
                encryptedContent
            );

            // 8. Process result
            const decryptedText = new TextDecoder().decode(decrypted);
            return this._denormalizeData(decryptedText);

        } catch (error) {
            console.error('Decryption failed:', {
                error,
                name: error.name,
                message: error.message,
                stack: error.stack,
                inputs: { publicSignals, privateKey }
            });
            throw new Error(`Decryption failed: ${error.message || error.name}`);
        }
    }

    // Helper methods
    _arrayBufferToHex(buffer) {
        return Array.from(new Uint8Array(buffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    _hexToBytes(hex) {
        if (hex.startsWith('0x')) hex = hex.slice(2);
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
        try {
            if (!this.testWallet) {
                // Create and store a test wallet
                this.testWallet = ethers.Wallet.createRandom();
                console.log('Created test wallet:', {
                    address: this.testWallet.address,
                    privateKey: this.testWallet.privateKey
                });
            }
            
            // Always use the same test wallet
            const privateKeyBytes = this._hexToBytes(this.testWallet.privateKey.slice(2));
            const publicKey = this.secp.getPublicKey(privateKeyBytes, true);
            
            console.log('Public key generation:', {
                requestedAddress: address,
                usingAddress: this.testWallet.address,
                publicKey: this._arrayBufferToHex(publicKey)
            });
            
            return publicKey;
        } catch (error) {
            console.error('Public key generation error:', error);
            throw new Error(`Failed to get public key: ${error.message}`);
        }
    }

    // Add Node.js version validation methods
    _validateSignals(signals) {
        const requiredFields = [
            'encryptedData',
            'initVector',
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
        const keyBytes = this._hexToBytes(privateKey.slice(2));
        if (!this._isValidPrivateKey(keyBytes)) {
            throw new Error('Invalid private key value');
        }
        return keyBytes;
    }

    // Helper method to check if key is valid
    _isValidPrivateKey(key) {
        try {
            return this.secp.utils.isValidPrivateKey(key);
        } catch {
            return false;
        }
    }
} 
