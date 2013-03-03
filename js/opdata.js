(function() {
  var Crypto, OPDATA01_HEADER, Opdata;

  Crypto = require('./crypto');

  OPDATA01_HEADER = '6F70646174613031';

  /**
   * @class Opdata
  */


  Opdata = (function() {
    /**
     * Opdata object
     * @constructor
     * @param {String} type                 Can be either 'item', 'itemKey' or 'profileKey'
     * @param {String|Buffer} encryptionKey The encryption key
     * @param {String|Buffer} hmacKey       The hmac key
    */

    function Opdata(encryptionKey, hmacKey) {
      this.encryptionKey = Crypto.toBuffer(encryptionKey);
      this.hmacKey = Crypto.toBuffer(hmacKey);
      if (this.encryptionKey.length !== 32) {
        console.log(this.encryptionKey.toString('hex'));
        throw new Error("Encryption key must be 32 bytes.");
      }
      if (this.hmacKey.length !== 32) {
        console.log(this.hmacKey.toString('hex'));
        throw new Error("HMAC Key must be 32 bytes");
      }
    }

    /**
     * Decrypt an object
     * @param {String} type Can be either 'item', 'itemKey' or 'profileKey'
     * @param {String|Buffer} object The encrypted opdata object
     * @return {String} The decrypted object
    */


    Opdata.prototype.decrypt = function(type, object) {
      var ciphertext, dataToHmac, expectedHmac, iv, keys, length, objectHmac, plaintext, rawtext;
      object = Crypto.toHex(object);
      if (type !== 'itemKey' && object.slice(0, 16).toUpperCase() !== OPDATA01_HEADER) {
        console.error('Not an opdata01 object');
        return false;
      }
      if (type === 'itemKey') {
        iv = Crypto.toBuffer(object.slice(0, 32));
        ciphertext = Crypto.toBuffer(object.slice(32, -64));
      } else {
        length = Crypto.parseLittleEndian(object.slice(16, 32));
        iv = Crypto.toBuffer(object.slice(32, 64));
        ciphertext = Crypto.toBuffer(object.slice(64, -64));
      }
      dataToHmac = Crypto.toBuffer(object.slice(0, -64));
      expectedHmac = object.slice(-64);
      objectHmac = Crypto.hmac(dataToHmac, this.hmacKey, 'sha256');
      if (objectHmac !== expectedHmac) {
        console.error('Hmac does not match');
        return false;
      }
      rawtext = Crypto.decrypt('aes-256-cbc', ciphertext, this.encryptionKey, iv, 'hex');
      if (type !== 'itemKey') {
        plaintext = Crypto.unpad(length, rawtext);
      }
      switch (type) {
        case 'item':
          return Crypto.toBuffer(plaintext).toString('utf8');
        case 'itemKey':
          return [rawtext.slice(0, 64), rawtext.slice(64)];
        case 'profileKey':
          keys = Crypto.hash(plaintext, 'sha512');
          return [keys.slice(0, 64), keys.slice(64)];
      }
    };

    /**
     * Encrypt plaintext as object
     * @param {String} type Can be either 'item', 'itemKey' or 'profileKey'
     * @param {Buffer} plaintext The data to be encrypted
     * @return {Buffer} The encrypted opdata object
    */


    Opdata.prototype.encrypt = function(type, plaintext) {
      var ciphertext, dataToHmac, endian, header, hmac, iv, paddedtext;
      iv = Crypto.randomBytes(16);
      if (type === 'itemKey') {
        paddedtext = plaintext;
      } else {
        paddedtext = Crypto.concat([iv, Crypto.pad(plaintext)]);
      }
      ciphertext = Crypto.encrypt('aes-256-cbc', paddedtext, this.encryptionKey, iv);
      if (type === 'itemKey') {
        dataToHmac = Crypto.concat([iv, ciphertext]);
      } else {
        header = Crypto.toBuffer(OPDATA01_HEADER);
        endian = Crypto.stringifyLittleEndian(plaintext.length);
        endian = Crypto.toBuffer(endian);
        dataToHmac = Crypto.concat([header, endian, iv, ciphertext]);
      }
      hmac = Crypto.hmac(dataToHmac, this.hmacKey, 'sha256');
      hmac = Crypto.toBuffer(hmac);
      return Crypto.concat([dataToHmac, hmac]);
    };

    return Opdata;

  })();

  module.exports = Opdata;

}).call(this);
