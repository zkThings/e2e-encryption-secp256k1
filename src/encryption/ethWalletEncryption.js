import { ETHEncryption } from './ethEncryption.browser.js';

export class ETHWalletEncryption extends ETHEncryption {
    constructor(provider = window.ethereum) {
        super();
        this.provider = provider;
    }

    async _deriveKeyFromSignature(address) {
        // Use exactly the same message for both operations
        const message = `Sign to access encrypted messages\nAddress: ${address.toLowerCase()}`;
        
        console.log(`Getting signature for address ${address}`);
        
        const signature = await this.provider.request({
            method: 'personal_sign',
            params: [message, address]
        });

        console.log('Got signature:', signature);

        // Derive key consistently
        const msgHash = ethers.utils.hashMessage(message);
        const derivedKey = ethers.utils.keccak256(
            ethers.utils.defaultAbiCoder.encode(
                ['bytes32', 'address'],
                [msgHash, address.toLowerCase()]
            )
        );

        console.log('Derived key:', derivedKey);
        return derivedKey;
    }

    async signAndEncrypt({ data, recipientAddress, signerAddress }) {
        try {
            // Get derived key
            const derivedPrivateKey = await this._deriveKeyFromSignature(signerAddress);

            // Store for comparison
            this.lastDerivedKey = derivedPrivateKey;

            // Override getPublicKey temporarily
            const originalGetPublicKey = this.getPublicKey.bind(this);
            this.getPublicKey = async () => {
                const pubKey = ethers.utils.computePublicKey(derivedPrivateKey, true);
                console.log('Using public key:', pubKey);
                return this._hexToBytes(pubKey.slice(2));
            };

            // Encrypt using derived key
            const result = await this.encryptFor(data, recipientAddress);

            // Restore original getPublicKey
            this.getPublicKey = originalGetPublicKey;

            return result;
        } catch (error) {
            console.error('Encryption error:', error);
            throw new Error(`Encryption failed: ${error.message}`);
        }
    }

    async signAndDecrypt({ publicSignals, address }) {
        try {
            // Get derived key
            const derivedPrivateKey = await this._deriveKeyFromSignature(address);

            // Compare with encryption key if available
            if (this.lastDerivedKey) {
                console.log('Key comparison:', {
                    encryptionKey: this.lastDerivedKey,
                    decryptionKey: derivedPrivateKey
                });
            }

            // Use derived key for decryption
            return this.decrypt({
                publicSignals,
                privateKey: derivedPrivateKey
            });
        } catch (error) {
            console.error('Decryption error:', error);
            throw new Error(`Decryption failed: ${error.message}`);
        }
    }
} 