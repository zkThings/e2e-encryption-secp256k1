
# @zkthings/e2e-encryption

Secure end-to-end encryption library with Ethereum address validation and browser support. Built for Web3 applications requiring private data handling.

[![npm version](https://badge.fury.io/js/@zkthings%2Fe2e-encryption.svg)](https://www.npmjs.com/package/@zkthings/e2e-encryption)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- End-to-end encryption using ECDH + AES-256-GCM
- Ethereum address validation built-in
- Browser-compatible implementation
- Support for notary/dual access encryption
- Works with any data type (objects, arrays, primitives)
- Data integrity verification
- Promise-based async API

## Installation

```bash
npm install @zkthings/e2e-encryption
# or
bun add @zkthings/e2e-encryption
```

## Quick Start

```javascript
const { ETHEncryption } = require('@zkthings/e2e-encryption');

// Initialize encryption
const encryption = new ETHEncryption();

// Example: Encrypt data for a recipient
const encrypted = await encryption.encryptFor(
    { secret: "sensitive data" },
    "0x742d35Cc6634C0532925a3b844Bc454e4438f44e", // recipient address
    recipientPublicKey // secp256k1 public key
);

// Later: Recipient decrypts data
const decrypted = await encryption.decrypt({
    publicSignals: encrypted.publicSignals,
    privateKey: recipientPrivateKey
});
```

## API Reference

### Node.js Usage (ETHEncryption)

```javascript
const { ETHEncryption } = require('@zkthings/e2e-encryption');
const encryption = new ETHEncryption();
```

#### `encryptFor(data, recipientAddress, recipientPublicKey)`
Encrypts data for a specific Ethereum address.

- `data`: Any JSON-serializable data
- `recipientAddress`: Ethereum address (with or without '0x' prefix)
- `recipientPublicKey`: secp256k1 public key
- Returns: `Promise<{ publicSignals: {...} }>`

#### `decrypt({ publicSignals, privateKey })`
Decrypts data using a private key.

- `publicSignals`: Encrypted data object
- `privateKey`: secp256k1 private key (with '0x' prefix)
- Returns: `Promise<any>` - Original data

### Browser Usage (ETHEncryptionBrowser)

```javascript
const { ETHEncryptionBrowser } = require('@zkthings/e2e-encryption');
const encryption = new ETHEncryptionBrowser();
```

Same API as Node.js version, but with browser-compatible implementations.

### Advanced Features

#### Notary Access
Encrypt data with dual access (both user and notary can decrypt):

```javascript
const encrypted = await encryption.encryptWithNotary(
    data,
    userAddress,
    userPublicKey,
    notaryAddress,
    notaryPublicKey
);

// User decryption
const userDecrypted = await encryption.decrypt({
    publicSignals: encrypted.publicSignals,
    privateKey: userPrivateKey,
    type: 'user'
});

// Notary decryption
const notaryDecrypted = await encryption.decrypt({
    publicSignals: encrypted.publicSignals,
    privateKey: notaryPrivateKey,
    type: 'notary'
});
```

#### Batch Decryption
Decrypt multiple encrypted items efficiently:

```javascript
const decryptedItems = await encryption.decryptMyMany(
    encryptedItems,
    privateKey
);
```

## Security

- Uses industry-standard ECDH for key exchange
- AES-256-GCM for symmetric encryption
- Includes authentication data to prevent tampering
- Ephemeral keys for perfect forward secrecy
- Secure key derivation using HKDF

## Error Handling

The library throws descriptive errors for common issues:

```javascript
try {
    await encryption.encryptFor(data, invalidAddress, publicKey);
} catch (error) {
    // Handles: Invalid address format, invalid keys, etc.
    console.error(error.message);
}
```

## Browser Compatibility

The browser version (`ETHEncryptionBrowser`) is specifically designed for browser environments:
- Uses `crypto.subtle` when available
- Falls back to polyfills when needed
- Handles browser-specific crypto API differences

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
