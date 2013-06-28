###*
 * This is a PBKDF2 implementation that is based on SJCL, but modified to work
 * with Node buffers and the native Node crypto library.
 * It's faster then SJCL, because it uses the native crypto library, but it's
 * not as fast as the native PBKDF2 function. It's main purpose is that it
 * works with SHA-256 ans SHA-12, because the native functions only work with
 * SHA-1.
###


# Dependencies
Crypto = require('crypto')


# Constants
SALT_SUFFIX = "00000001"


class Hmac

  ###*
   * - key {buffer} : The key to derive data from.
   * - size {number} : The SHA algorithm to use.
  ###
  constructor: (@key, size) ->
    @mode = "sha#{size}"


  ###*
   * Hash data
   * - buffer {buffer} : The data to hash.
   * > buffer - the hashed data
  ###
  encrypt: (buffer) ->
    binary = Crypto.createHmac(@mode, @key).update(buffer).digest()


###*
 * PBKDF2
 * - password {string|buffer} : The password to derive a key from.
 * - salt {string|buffer} : The salt.
 * - [count=10000] {number} : Number of iterations.
 * - [length=512] {number} : The SHA algorithm to use.
 * > buffer - the derived key
###
module.exports = (password, salt, count=10000, length=512) ->

  if typeof password is 'string'
    password = new Buffer(password)

  if typeof salt is 'string'
    salt = new Buffer(salt + SALT_SUFFIX, 'hex')
  else
    salt = Buffer.concat [salt, new Buffer(SALT_SUFFIX, 'hex')]

  hmac = new Hmac(password, length)
  last = xorsum = hmac.encrypt(salt)
  bit_length = length / 8

  i = 1
  while i++ < count
    xorsum = hmac.encrypt(xorsum)
    j = -1
    while ++j < bit_length
      last[j] ^= xorsum[j]

  return last
