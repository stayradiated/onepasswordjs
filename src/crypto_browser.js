// Generated by CoffeeScript 1.7.1

/**
 * @fileOverview A collection of cryptographic functions that work in most browsers.
 */

(function() {
  var BLOCKSIZE, Crypto, Gibberish, jsSHA, sjcl;

  Gibberish = require('../libs/gibberish-aes');

  jsSHA = require('../libs/sha');

  sjcl = require('../libs/sjcl');

  BLOCKSIZE = 16;

  Crypto = {

    /**
     * Encipher data
     * @param {Buffer} plaintext The data to encrypt.
     * @param {String|Buffer} key The key to encrypt with. Can be a Buffer or hex encoded string.
     * @param {String|Buffer} iv The IV. Can be a Buffer or hex encoded string.
     * @param {string} [encoding=buffer] The format to return the encrypted data at.
     * @return {String} The encrypted data.
     */
    encrypt: function(plaintext, key, iv, encoding) {
      var base64, blocks, ciphertext;
      if (encoding == null) {
        encoding = "buffer";
      }
      key = this.toBuffer(key);
      iv = this.toBuffer(iv);
      blocks = Gibberish.rawEncrypt(plaintext, key, iv);
      base64 = Gibberish.Base64.encode(blocks, false);
      if (encoding === 'base64') {
        return base64;
      }
      ciphertext = Gibberish.Base64.decode(base64);
      if (encoding === 'hex') {
        return Gibberish.a2h(ciphertext);
      }
      if (encoding === 'buffer') {
        return ciphertext;
      } else {
        throw new Error("Encoding not supported");
      }
    },

    /**
     * Decipher encrypted data.
     * @param {String|Buffer} ciphertext The data to decipher. Must be a multiple of the blocksize.
     * @param {String|Buffer} key The key to decipher the data with.
     * @param {String|Buffer} iv The initialization vector to use.
     * @param {String} [encoding=buffer] The format to return the decrypted contents as.
     * @return {Buffer|String} The decrypted contents.
     */
    decrypt: function(ciphertext, key, iv, encoding) {
      var binary, bytes, hex;
      if (encoding == null) {
        encoding = "buffer";
      }
      iv = this.toBuffer(iv);
      key = this.toBuffer(key);
      ciphertext = this.toBuffer(ciphertext);
      binary = Gibberish.rawDecrypt(ciphertext, key, iv, true);
      hex = this.bin2hex(binary);
      if (encoding === 'hex') {
        return hex;
      }
      bytes = Gibberish.h2a(hex);
      if (encoding === 'base64') {
        return Gibberish.Base64.encode(bytes);
      }
      if (encoding === "buffer") {
        return bytes;
      } else {
        throw new Error("Encoding now supported");
      }
    },

    /**
     * Generate keys from password using PKDF2-HMAC-SHA512.
     * @param {String} password The password.
     * @param {String|Buffer} salt The salt.
     * @param {Number} [iterations=10000] The numbers of iterations.
     * @param {Numbers} [keysize=512] The length of the derived key in bits.
     * @return {String} Returns the derived key encoded as hex.
     */
    pbkdf2: function(password, salt, iterations, keysize) {
      var bits, hmac, self;
      if (iterations == null) {
        iterations = 10000;
      }
      if (keysize == null) {
        keysize = 512;
      }
      self = this;
      hmac = (function() {
        function hmac(key) {
          this.key = sjcl.codec.bytes.fromBits(key);
        }

        hmac.prototype.encrypt = function(sjclArray) {
          var bits, byteArray, hex;
          byteArray = sjcl.codec.bytes.fromBits(sjclArray);
          hex = self.hmac(byteArray, this.key, keysize);
          bits = sjcl.codec.hex.toBits(hex);
          return bits;
        };

        return hmac;

      })();
      salt = sjcl.codec.hex.toBits(this.toHex(salt));
      bits = sjcl.misc.pbkdf2(password, salt, iterations, keysize, hmac);
      return sjcl.codec.hex.fromBits(bits);
    },

    /**
     * Cryptographically hash data using HMAC.
     * @param {String|Buffer} data The data to be hashed.
     * @param {String|Buffer} key The key to use with HMAC.
     * @param {Number} [keysize=512] The keysize for the hash function.
     * @return {String} The hmac digest encoded as hex.
     */
    hmac: function(data, key, keysize) {
      var input, mode;
      if (keysize == null) {
        keysize = 512;
      }
      data = this.toHex(data);
      key = this.toHex(key);
      mode = "SHA-" + keysize;
      input = new jsSHA(data, "HEX");
      return input.getHMAC(key, "HEX", mode, "HEX");
    },

    /**
     * Create a hash digest of data.
     * @param {String|Buffer} data The data to hash.
     * @param {Number} [keysize=512] The keysize for the hash function.
     * @return {String} The hash digest encoded as hex.
     */
    hash: function(data, keysize) {
      var input, mode;
      if (keysize == null) {
        keysize = 512;
      }
      data = this.toHex(data);
      mode = "SHA-" + keysize;
      input = new jsSHA(data, "HEX");
      return input.getHash(mode, "HEX");
    },

    /**
     * Prepend padding to data to make it fill the blocksize.
     * @param {Buffer} data The data to pad.
     * @return {Buffer} The data with padding added.
     */
    pad: function(data) {
      var bytesToPad, padding;
      bytesToPad = BLOCKSIZE - (data.length % BLOCKSIZE);
      padding = this.randomBytes(bytesToPad);
      return this.concat([padding, data]);
    },

    /**
     * Remove padding from text.
     * @param {Numbers} plaintextLength The length of the plaintext in bytes.
     * @param {String|Buffer} data The data to remove the padding as a string encoded as hex or a buffer.
     * @return {String} The data with the padding removed encoded as hex.
     */
    unpad: function(plaintextLength, data) {
      data = this.toHex(data);
      plaintextLength *= 2;
      return data.slice(-plaintextLength);
    },

    /**
     * Generates cryptographically strong pseudo-random data.
     * @param {Numbers} length How many bytes of data you want.
     * @return {Buffer} The random data as a Buffer.
     */
    randomBytes: function(length) {
      var array, byte, _i, _len, _results;
      array = new Uint8Array(length);
      window.crypto.getRandomValues(array);
      _results = [];
      for (_i = 0, _len = array.length; _i < _len; _i++) {
        byte = array[_i];
        _results.push(byte);
      }
      return _results;
    },

    /**
     * Convert data to a Buffer
     * @param {String|Buffer} data The data to be converted. If a string, must be encoded as hex.
     * @param {String} [encoding=hex] The format of the data to convert.
     * @return {Buffer} The data as a Buffer
     */
    toBuffer: function(data, encoding) {
      if (encoding == null) {
        encoding = 'hex';
      }
      if (Array.isArray(data)) {
        return data;
      }
      switch (encoding) {
        case 'base64':
          return Gibberish.base64.decode(data);
        case 'hex':
          return Gibberish.h2a(data);
        case 'utf8':
          return Gibberish.s2a(data);
        default:
          throw new Error("Encoding not supported");
      }
    },

    /**
     * Convert data to hex.
     * @param {String|Buffer} data The data to be converted.
     * @return {String} The data encoded as hex.
     */
    toHex: function(data) {
      if (Array.isArray(data)) {
        return Gibberish.a2h(data);
      }
      return data;
    },

    /**
     * Convert base64 to Buffer.
     * @param {String} data A base64 encoded string.
     * @return {Buffer} The base64 string as a Buffer.
     */
    fromBase64: function(data) {
      return Gibberish.Base64.decode(data);
    },

    /**
     * Join an array of buffers together.
     * @param {Array} buffers An array of buffers.
     * @return {Buffer} The buffers joined together.
     */
    concat: function(buffers) {
      return Array.prototype.concat.apply(buffers[0], buffers.slice(1));
    },

    /**
     * Parse a litte endian number.
     * @author Jim Rogers {@link http://www.jimandkatrin.com/CodeBlog/post/Parse-a-little-endian.aspx}
     * @param {String} hex The little endian number.
     * @return {Number} The little endian converted to a number.
     */
    parseLittleEndian: function(hex) {
      var pow, result;
      result = 0;
      pow = 0;
      while (hex.length > 0) {
        result += parseInt(hex.substring(0, 2), 16) * Math.pow(2, pow);
        hex = hex.substring(2, hex.length);
        pow += 8;
      }
      return result;
    },

    /**
     * Convert an integer into a little endian.
     * @param {Number} number The integer you want to convert.
     * @param {Boolean} [pad=true] Pad the little endian with zeroes.
     * @return {String} The little endian.
     */
    stringifyLittleEndian: function(number, pad) {
      var endian, i, multiplier, padding, power, remainder, value, _i;
      if (pad == null) {
        pad = true;
      }
      power = Math.floor((Math.log(number) / Math.LN2) / 8) * 8;
      multiplier = Math.pow(2, power);
      value = Math.floor(number / multiplier);
      remainder = number % multiplier;
      endian = "";
      if (remainder > 255) {
        endian += this.stringifyLittleEndian(remainder, false);
      } else if (power !== 0) {
        endian += this.dec2hex(remainder);
      }
      endian += this.dec2hex(value);
      if (pad) {
        padding = 16 - endian.length;
        for (i = _i = 0; _i < padding; i = _i += 1) {
          endian += "0";
        }
      }
      return endian;
    },

    /**
     * Turn a decimal into a hexadecimal.
     * @param {Number} dec The decimal.
     * @return {String} The hexadecimal.
     */
    dec2hex: function(dec) {
      var hex;
      hex = dec.toString(16);
      if (hex.length < 2) {
        hex = "0" + hex;
      }
      return hex;
    },

    /**
     * Convert a binary string into a hex string.
     * @param {String} binary The binary encoded string.
     * @return {String} The hex encoded string.
     */
    bin2hex: function(binary) {
      var char, hex, _i, _len;
      hex = "";
      for (_i = 0, _len = binary.length; _i < _len; _i++) {
        char = binary[_i];
        hex += char.charCodeAt(0).toString(16).replace(/^([\dA-F])$/i, "0$1");
      }
      return hex;
    },

    /**
     * Generate a uuid.
     * @param {Number} [length=32] The length of the UUID.
     * @return {String} The UUID.
     */
    generateUuid: function(length) {
      var bytes, hex;
      if (length == null) {
        length = 32;
      }
      length /= 2;
      bytes = this.randomBytes(length);
      return hex = this.toHex(bytes).toUpperCase();
    }
  };

  module.exports = Crypto;

}).call(this);
