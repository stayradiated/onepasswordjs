'use strict';

/**
 * A collection of cryptographic functions.
 * The important ones (AES, SHA, HMAC ...) are all wrappers for the openssl
 * library built into Node.
 */

var nodeCrypto = require('crypto');

var BLOCKSIZE = 16;

var Crypto = {

  /**
    * crypto.encrypt
    *
    * Encrypt data using AES256 in CBC mode.
    *
    * - plaintext {Buffer} : The data to encrypt.
    * - key {String|Buffer} : The key to encrypt with.
    * - iv {String|Buffer} : The initialization vector.
    * - [encoding] {string} : The format to return the encrypted data in.
    * > buffer
    */

  encrypt: function(plaintext, key, iv, encoding) {
    iv = this.toBuffer(iv);
    key = this.toBuffer(key);
    var cipher = nodeCrypto.createCipheriv('aes-256-cbc', key, iv);
    cipher.setAutoPadding(false);
    var buffer = this.concat([cipher.update(plaintext), cipher.final()]);
    if (encoding !== undefined) {
      return buffer.toString(encoding);
    }
    return buffer;
  },


  /**
    * crypto.decrypt
    *
    * Decrypt encrypted data using AES256 in CBC mode
    *
    * - ciphertext {String|Buffer} : The data to decipher. Length must be a
    *   multiple of the blocksize.
    * - key {String|Buffer} : The key to decipher with.
    * - iv {String|Buffer} : The initialization vector.
    * - [encoding] {String} : The format to return the decrypted contents in.
    * > buffer
    */

  decrypt: function(ciphertext, key, iv, encoding) {
    iv = this.toBuffer(iv);
    key = this.toBuffer(key);
    ciphertext = this.toBuffer(ciphertext);
    var cipher = nodeCrypto.createDecipheriv('aes-256-cbc', key, iv);
    cipher.setAutoPadding(false);
    var buffer = this.concat([cipher.update(ciphertext), cipher.final()]);
    if (encoding !== undefined) {
      return buffer.toString(encoding);
    }
    return buffer;
  },


  /**
    * crypto.pbkdf2
    *
    * Generate keys from password using PKDF2-HMAC-SHA512.
    *
    * - password {String|Buffer} : The password.
    * - salt {String|Buffer} : The salt.
    * - [iterations=10000] {Number} : The numbers of iterations.
    * - [keysize=512] {Number} : The SHA algorithm to use.
    * > string
    */
  pbkdf2: require('./crypto_pbkdf2'),


  /**
    * crypto.hmac
    *
    * Cryptographically hash data using HMAC.
    *
    * - data {String|Buffer} : The data to be hashed.
    * - key {String|Buffer} : The key to use with HMAC.
    * - keysize {Number} : The type of hash to use, e.g. 256 or 512.
    * - [encoding] {String} : Data encoding to return as. If left unspecified,
    *   it will return as a buffer.
    * > buffer
    */

  hmac: function(data, key, keysize, encoding) {
    data = this.toBuffer(data);
    key = this.toBuffer(key);
    var mode = 'sha' + keysize;
    var hmac = nodeCrypto.createHmac(mode, key);
    hmac.update(data);
    if (encoding !== undefined) {
      return hmac.digest(encoding);
    }
    return hmac.digest();
  },


  /**
    * crypto.hash
    *
    * Create a hash digest of data.
    *
    * - data {string|buffer} : The data to hash.
    * - keysize {number} : The type of hash to use, e.g. 256 or 512.
    * - [encoding] {string} : Data encoding to return as. If left unspecified,
    *   it will return as a buffer.
    * > buffer
    */

  hash: function(data, keysize, encoding) {
    data = this.toBuffer(data);
    var mode = 'sha' + keysize;
    var hash = nodeCrypto.createHash(mode);
    hash.update(data);
    if (encoding !== undefined) {
      return hash.digest(encoding);
    }
    return hash.digest();
  },


  /**
    * crypto.pad
    *
    * Prepend padding to data to make it fill the blocksize.
    *
    * - data {Buffer} : The data to pad.
    * > buffer
    */

  pad: function(data) {
    var paddingLength = BLOCKSIZE - (data.length % BLOCKSIZE);
    var padding = this.randomBytes(paddingLength);
    return Buffer.concat([padding, data]);
  },


  /**
    * crypto.unpad
    *
    * Remove padding from text.
    *
    * - plaintextLength {number} : The length of the plaintext in bytes.
    * - data {buffer} : The data to remove the padding from. Can be a hex string
    *   or a buffer.
    * > buffer
    */
  unpad: function(plaintextLength, data) {
    return data.slice(-plaintextLength);
  },


  /**
    * crypto.randomBytes
    *
    * Generates cryptographically strong pseudo-random data.
    *
    * - length {Number} : How many bytes of data you need.
    * > buffer
    */

  randomBytes: function(length) {
    return nodeCrypto.randomBytes(length);
  },


  /**
    * crypto.randomValue
    *
    * Generate a cryptographically strong pseudo-random number.
    *
    * Very similar to Math.random() except it's more random.
    * > float - between 0 and 1
    */

  randomValue: function() {
    var bytes = this.randomBytes(4).toString('hex');
    var decimal = parseInt(bytes, 16);
    return decimal * Math.pow(2, -32);
  },

  /**
    * crypto.toBuffer
    *
    * Convert data to a Buffer
    *
    * - data {String|Buffer} : The string to be converted.
    * - [encoding=hex] {String} : The format of the data to convert from.
    * > buffer
    */

  toBuffer: function(data, encoding) {
    if (encoding === undefined) { encoding = 'hex'; }
    if (data instanceof Buffer) { return data; }
    return new Buffer(data, encoding);
  },


  /**
    * crypto.toHex
    *
    * Convert data to hex.
    *
    * - data {String|Buffer} : The data to be converted.
    * > string
    */

  toHex: function(data) {
    if (data instanceof Buffer) {
      return data.toString('hex');
    }
    return data;
  },


  /**
    * crypto.fromBase64
    *
    * Convert base64 to Buffer.
    *
    * - data {String} : A base64 encoded string.
    * > buffer
    */

  fromBase64: function(data) {
    return new Buffer(data, 'base64');
  },


  /**
    * crypto.concat
    *
    * Join an array of buffers together.
    *
    * - buffers {Array} : An array of buffers.
    * > buffer
    */

  concat: function(buffers) {
    return Buffer.concat(buffers);
  },


  /**
    * crypto.parseLittleEndian
    *
    * Parse a litte endian number. Original JS version by Jim Rogers.
    * http://www.jimandkatrin.com/CodeBlog/post/Parse-a-little-endian.aspx
    *
    * - hex {buffer or string} : The little endian number.
    * > number - the little endian converted to a number.
    */

  parseLittleEndian: function(hex) {
    hex = this.toHex(hex);
    var result = 0;
    var pow = 0;
    var i = 0;
    var len = hex.length - 1;
    while (i < len) {
      result += parseInt(hex.slice(i++, +(i++) + 1 || 9e9), 16) * Math.pow(2, pow);
      pow += 8;
    }
    return result;
  },


  /**
    * crypto.litteEndian
    *
    * Convert an integer into a little endian.
    *
    * - number {Number} number The integer you want to convert.
    * - [pad=true] {Boolean} : Pad the little endian with zeroes.
    * > string - encoded as hex
    */

  littleEndian: function(number, pad) {
    if (pad === undefined) pad = true;
    var power = Math.floor((Math.log(number) / Math.LN2) / 8) * 8;
    var multiplier = Math.pow(2, power);
    var value = Math.floor(number / multiplier);
    var remainder = number % multiplier;
    var endian = "";
    if (remainder > 255) {
      endian += this.stringifyLittleEndian(remainder, false);
    } else if (power !== 0) {
      endian += this.dec2hex(remainder);
    }
    endian += this.dec2hex(value);
    if (pad) {
      var padding = 16 - endian.length;
      for (var i = 0; i < padding; i += 1) endian += "0";
    }
    return endian;
  },


  /**
    * crypto.dec2hex
    *
    * Turn a decimal into a hexadecimal.
    *
    * - dec {Number} : The decimal.
    * > string
    */

  dec2hex: function(dec) {
    var hex;
    hex = dec.toString(16);
    if (hex.length < 2) {
      hex = '0' + hex;
    }
    return hex;
  },


  /**
    * crypto.bin2hex
    *
    * Convert a binary string into a hex string.
    *
    * - binary {String} : The binary encoded string.
    * > string
    */

  bin2hex: function(binary) {
    var hex = "";
    for (var i = 0, len = binary.length; i < len; i += 1) {
      var char = binary[i];
      hex += char.charCodeAt(0).toString(16).replace(/^([\dA-F])$/i, '0$1');
    }
    return hex;
  },


  /**
    * crypto.generateUuid
    *
    * Generate a uuid.
    *
    * - param {Number} [length=32] The length of the UUID.
    * > string
    */

  generateUuid: function(length) {
    if (! length) { length = 32; }
    length /= 2;
    return this.randomBytes(length).toString('hex').toUpperCase();
  }
};

module.exports = Crypto;
