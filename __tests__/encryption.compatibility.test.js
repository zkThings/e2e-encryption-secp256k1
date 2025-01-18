const ETHEncryption = require('../src/encryption/ethEncryption');
const BrowserEncryption = require('../src/encryption/ethEncryption.browser');
const secp256k1 = require('secp256k1');
const crypto = require('crypto');

describe('Encryption Compatibility Tests', () => {
    let nodeEncryption;
    let browserEncryption;
    let communityKeys;
    let testData;

    beforeEach(() => {
        nodeEncryption = new ETHEncryption();
        browserEncryption = new BrowserEncryption();

        // Generate test community keys
        let privateKey = crypto.randomBytes(32);
        while (!secp256k1.privateKeyVerify(privateKey)) {
            privateKey = crypto.randomBytes(32);
        }
        
        communityKeys = {
            privateKey: `0x${privateKey.toString('hex')}`,
            publicKey: secp256k1.publicKeyCreate(privateKey),
            address: '0x' + crypto.randomBytes(20).toString('hex')
        };

        testData = {
            message: 'Test message',
            timestamp: new Date().toISOString(),
            number: 42,
            nested: {
                value: 'nested value'
            }
        };
    });

    describe('Browser -> Node Compatibility', () => {
        test('Node should decrypt Browser-encrypted data', async () => {
            // Browser encrypts
            const browserEncrypted = await browserEncryption.encryptFor(
                testData,
                communityKeys.address,
                communityKeys.publicKey
            );

            // Format for Node decryption
            const formattedForNode = {
                publicSignals: {
                    ...browserEncrypted,
                    forAddress: browserEncrypted.communityId
                }
            };

            // Node decrypts
            const decryptedByNode = await nodeEncryption.decrypt({
                publicSignals: formattedForNode.publicSignals,
                privateKey: communityKeys.privateKey
            });

            expect(decryptedByNode).toEqual(testData);
        });

        test('should handle different data types', async () => {
            const testCases = [
                null,
                undefined,
                123,
                'string',
                { obj: 'test' },
                [1, 2, 3],
                true,
                new Date().toISOString()
            ];

            for (const testCase of testCases) {
                const browserEncrypted = await browserEncryption.encryptFor(
                    testCase,
                    communityKeys.address,
                    communityKeys.publicKey
                );

                const formattedForNode = {
                    publicSignals: {
                        ...browserEncrypted,
                        forAddress: browserEncrypted.communityId
                    }
                };

                const decryptedByNode = await nodeEncryption.decrypt({
                    publicSignals: formattedForNode.publicSignals,
                    privateKey: communityKeys.privateKey
                });

                expect(decryptedByNode).toEqual(testCase);
            }
        });

        test('should fail with tampered data', async () => {
            const browserEncrypted = await browserEncryption.encryptFor(
                testData,
                communityKeys.address,
                communityKeys.publicKey
            );

            // Tamper with encrypted data
            browserEncrypted.encryptedData = 
                browserEncrypted.encryptedData.replace('a', 'b');

            const formattedForNode = {
                publicSignals: {
                    ...browserEncrypted,
                    forAddress: browserEncrypted.communityId
                }
            };

            await expect(
                nodeEncryption.decrypt({
                    publicSignals: formattedForNode.publicSignals,
                    privateKey: communityKeys.privateKey
                })
            ).rejects.toThrow('Data integrity check failed');
        });
    });

    describe('Node -> Browser Compatibility', () => {
        test('Browser should decrypt Node-encrypted data', async () => {
            // Node encrypts
            const nodeEncrypted = await nodeEncryption.encryptFor(
                testData,
                communityKeys.address,
                communityKeys.publicKey
            );

            // Need to extract from publicSignals wrapper
            const formattedForBrowser = nodeEncrypted.publicSignals ? {
                encryptedData: nodeEncrypted.publicSignals.encryptedData,
                initVector: nodeEncrypted.publicSignals.initVector,
                verificationTag: nodeEncrypted.publicSignals.verificationTag,
                ephemeralPublicKey: nodeEncrypted.publicSignals.ephemeralPublicKey,
                communityId: nodeEncrypted.publicSignals.forAddress,
                version: nodeEncrypted.publicSignals.version
            } : nodeEncrypted;

            // Browser decrypts
            const decryptedByBrowser = await browserEncryption.decrypt(
                formattedForBrowser,
                communityKeys.privateKey
            );

            expect(decryptedByBrowser).toEqual(testData);
        });
    });

    describe('Data Format Validation', () => {
        test('Browser encryption should produce valid format', async () => {
            const encrypted = await browserEncryption.encryptFor(
                testData,
                communityKeys.address,
                communityKeys.publicKey
            );

            expect(encrypted).toHaveProperty('encryptedData');
            expect(encrypted).toHaveProperty('initVector');
            expect(encrypted).toHaveProperty('verificationTag');
            expect(encrypted).toHaveProperty('ephemeralPublicKey');
            expect(encrypted).toHaveProperty('communityId');
            expect(encrypted).toHaveProperty('version');

            expect(typeof encrypted.encryptedData).toBe('string');
            expect(typeof encrypted.initVector).toBe('string');
            expect(typeof encrypted.verificationTag).toBe('string');
            expect(typeof encrypted.ephemeralPublicKey).toBe('string');
            expect(typeof encrypted.communityId).toBe('string');
            expect(typeof encrypted.version).toBe('string');
        });

        test('should handle large data', async () => {
            const largeData = {
                array: Array(1000).fill('test'),
                nested: {
                    deep: {
                        deeper: {
                            deepest: 'value'
                        }
                    }
                }
            };

            const browserEncrypted = await browserEncryption.encryptFor(
                largeData,
                communityKeys.address,
                communityKeys.publicKey
            );

            const formattedForNode = {
                publicSignals: {
                    ...browserEncrypted,
                    forAddress: browserEncrypted.communityId
                }
            };

            const decryptedByNode = await nodeEncryption.decrypt({
                publicSignals: formattedForNode.publicSignals,
                privateKey: communityKeys.privateKey
            });

            expect(decryptedByNode).toEqual(largeData);
        });
    });

    describe('Error Handling', () => {
        test('should reject invalid public keys', async () => {
            await expect(
                browserEncryption.encryptFor(
                    testData,
                    communityKeys.address,
                    'invalid-key'
                )
            ).rejects.toThrow();
        });

        test('should reject invalid community ID', async () => {
            await expect(
                browserEncryption.encryptFor(
                    testData,
                    'invalid-address',
                    communityKeys.publicKey
                )
            ).rejects.toThrow();
        });

        test('should reject missing required parameters', async () => {
            await expect(
                browserEncryption.encryptFor(
                    testData,
                    null,
                    communityKeys.publicKey
                )
            ).rejects.toThrow();

            await expect(
                browserEncryption.encryptFor(
                    testData,
                    communityKeys.address,
                    null
                )
            ).rejects.toThrow();
        });
    });

    describe('Performance', () => {
        test('should handle concurrent operations', async () => {
            const operations = Array(10).fill(testData).map(() => 
                browserEncryption.encryptFor(
                    testData,
                    communityKeys.address,
                    communityKeys.publicKey
                )
            );
            await expect(Promise.all(operations)).resolves.toBeDefined();
        });

        test('should complete encryption within reasonable time', async () => {
            const start = Date.now();
            await browserEncryption.encryptFor(
                testData,
                communityKeys.address,
                communityKeys.publicKey
            );
            expect(Date.now() - start).toBeLessThan(1000); // Should complete within 1s
        });
    });
}); 