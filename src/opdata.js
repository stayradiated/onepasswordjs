'use strict';

// Dependencies
var Crypto = require('./crypto');

// Constants
var OPDATA_HEADER = new Buffer('6F70646174613031', 'hex');
var OPDATA_HEADER_HEX = OPDATA_HEADER.toString('hex');

/*
 * Opdata object. Construct a new instance with the keys and then use it to
 * encrypt and decrypt data.
 * - encryption {buffer} : The encryption key
 * - hmac {buffer} : The hmac key
 */
function Opdata(encryption, hmac) {
  this.encryption = encryption;
  this.hmac = hmac;

  if (this.encryption.length !== 32) {
    throw new Error("Encryption key must be 32 bytes.");
  }

  if (this.hmac.length !== 32) {
    throw new Error("HMAC Key must be 32 bytes");
  }
}


/*
 * Decrypt an object
 * - type {string} : Can be either buffer, item, itemKey or profileKey
 * - object {buffer} : The encrypted opdata object
 * > string or buffer - The decrypted object
 */

Opdata.prototype.decrypt = function(type, buffer) {

  if (type !== 'itemKey' &&
      buffer.slice(0, 8).toString('hex') !== OPDATA_HEADER_HEX) {
    console.error('Not an opdata01 object');
    return false;
  }

  var iv;
  var ciphertext;
  var length = 0;

  if (type === 'itemKey') {
    iv = buffer.slice(0, 16);
    ciphertext = buffer.slice(16, -32);
  } else {
    length = Crypto.parseLittleEndian(buffer.slice(8, 16));
    iv = buffer.slice(16, 32);
    ciphertext = buffer.slice(32, -32);
  }

  var dataToHmac = buffer.slice(0, -32);
  var expectedHmac = buffer.slice(-32).toString('hex');

  // Verify HMAC
  var hmac = Crypto.hmac(dataToHmac, this.hmac, 256, 'hex');
  if (hmac !== expectedHmac) { return false; }

  // Decipher
  var rawBuffer = Crypto.decrypt(ciphertext, this.encryption, iv);

  var plaintext;

  // ItemKeys are not padded
  if (type !== 'itemKey') {
    plaintext = Crypto.unpad(length, rawBuffer);
  }

  // Depending on the type of data we are decrypting
  switch (type) {
    case 'buffer':
      return plaintext;
    case 'item':
      return plaintext.toString('utf8');
    case 'itemKey':
      return [rawBuffer.slice(0, 32), rawBuffer.slice(32)];
    case 'profileKey':
      var keys = Crypto.hash(plaintext, 512);
      return [keys.slice(0, 32), keys.slice(32)];
  }
};


/*
 * Encrypt plaintext as object
 * - type {String} : Can be either 'item', 'itemKey' or 'profileKey'
 * - plaintext {Buffer} : The data to be encrypted
 * > buffer - the encrypted opdata object
 */

Opdata.prototype.encrypt = function(type, plaintext) {

  // Generate a random 16 byte IV
  var iv = Crypto.randomBytes(16);

  // Pad the plaintext with the IV and block padding
  var paddedtext;
  if (type === 'itemKey') {
    paddedtext = plaintext;
  } else {
    paddedtext = Crypto.concat([iv, Crypto.pad(plaintext)]);
  }

  // Encrypt using AES 256 in CBC mode
  var ciphertext = Crypto.encrypt(paddedtext, this.encryption, iv);

  // Header data
  var endian;
  var header;
  var dataToHmac;
  if (type === 'itemKey') {
    dataToHmac = Crypto.concat([iv, ciphertext]);
  } else {
    header = OPDATA_HEADER;
    endian = Crypto.toBuffer(Crypto.littleEndian(plaintext.length));
    dataToHmac = Crypto.concat([header, endian, iv, ciphertext]);
  }

  // Generate a HMAC using SHA256
  var hmac = Crypto.hmac(dataToHmac, this.hmac, 256);

  return Crypto.concat([dataToHmac, hmac]);
};

module.exports = Opdata;
