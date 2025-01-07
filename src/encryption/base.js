class Encryption {
  constructor() {
    if (this.constructor === Encryption) {
      throw new Error("Can't instantiate abstract base class!");
    }
  }

  async encrypt(data) {
    throw new Error('Method encrypt() must be implemented');
  }

  async decrypt(params) {
    throw new Error('Method decrypt() must be implemented');
  }
}

module.exports = Encryption; 