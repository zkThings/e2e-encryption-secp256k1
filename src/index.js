// Main package entry
const ETHEncryption = require('./encryption/ethEncryption');
const ETHEncryptionBrowser = require('./encryption/ethEncryption.browser');

module.exports = { 
    ETHEncryption,        // Standard secure encryption
    ETHEncryptionBrowser, // Browser-compatible encryption
}; 