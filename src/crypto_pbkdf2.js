'use strict';

/**
 * This is a PBKDF2 implementation that is based on SJCL, but modified to work
 * with Node buffers and the native Node crypto library.
 * It's faster then SJCL, because it uses the native crypto library, but it's
 * not as fast as the native PBKDF2 function. It's main purpose is that it
 * works with SHA-256 ans SHA-12, because the native functions only work with
 * SHA-1.
 */

var Crypto = require('crypto');

// Constants
var SALT_SUFFIX = "00000001";

/**
 * - key {buffer} : The key to derive data from.
 * - size {number} : The SHA algorithm to use.
 */
function Hmac(key, size) {
  this.key = key;
  this.mode = "sha" + size;
}


/**
 * Hash data
 * - buffer {buffer} : The data to hash.
 * > buffer - the hashed data
 */

Hmac.prototype.encrypt = function(buffer) {
  return Crypto.createHmac(this.mode, this.key).update(buffer).digest();
};


/**
 * PBKDF2
 * - password {string|buffer} : The password to derive a key from.
 * - salt {string|buffer} : The salt.
 * - [count=10000] {number} : Number of iterations.
 * - [length=512] {number} : The SHA algorithm to use.
 * > buffer - the derived key
 */

module.exports = function(password, salt, count, length) {

  if (count == null) { count = 10000; }
  if (length == null) { length = 512; }

  if (typeof password === 'string') {
    password = new Buffer(password);
  }

  if (typeof salt === 'string') {
    salt = new Buffer(salt + SALT_SUFFIX, 'hex');
  } else {
    salt = Buffer.concat([salt, new Buffer(SALT_SUFFIX, 'hex')]);
  }

  var hmac = new Hmac(password, length);
  var xorsum = hmac.encrypt(salt);
  var last = xorsum;
  var bitLength = length / 8;

  var i = 1;
  var j;

  while (i < count) {
    xorsum = hmac.encrypt(xorsum);
    j = 0;
    while (j < bitLength) {
      last[j] ^= xorsum[j];
      j += 1;
    }
    i += 1;
  }
  return last;
};
