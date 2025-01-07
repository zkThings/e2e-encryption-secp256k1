import { AES256GCM } from '@zkthings/private-data-aes256'

// Initialize encryption
const encryption = new AES256GCM()

// Generate user keys
const userKeys = encryption.generateKeyPair()

// 1. Basic encryption (just user access)
const { publicSignals: basicSignals } = await encryption.encryptFor(
  { amount: 1000 },
  userKeys.publicKey
)

// Only user can decrypt
const basicDecrypted = await encryption.decryptMine({
  publicSignals: basicSignals,
  privateKey: userKeys.privateKey
})

// 2. Notary encryption (dual access)
const bankKeys = encryption.generateKeyPair()
const { publicSignals: notarySignals } = await encryption.encryptWithNotary(
  { amount: 1000 },
  userKeys.publicKey,
  bankKeys.publicKey
)

// Both can decrypt:
const userDecrypted = await encryption.decrypt({
  publicSignals: notarySignals,
  privateKey: userKeys.privateKey,
  type: 'user'
})

const bankDecrypted = await encryption.decrypt({
  publicSignals: notarySignals,
  privateKey: bankKeys.privateKey,
  type: 'notary'
})