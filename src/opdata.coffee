# Javascript implementation of the Agile Bits opdata01 format
# http://learn.agilebits.com/1Password4/Security/keychain-design.html#opdata

Crypto = require('./crypto')

# Constants
OPDATA01_HEADER = '6F70646174613031'

###*
 * @class Opdata
###

class Opdata

  ###*
   * Opdata object
   * @constructor
   * @param {String|Buffer} encryptionKey The encryption key
   * @param {String|Buffer} hmacKey       The hmac key
  ###

  constructor: (encryptionKey, hmacKey) ->
    @encryptionKey = Crypto.toBuffer(encryptionKey)
    @hmacKey = Crypto.toBuffer(hmacKey)

    if @encryptionKey.length isnt 32
      console.log @encryptionKey.toString('hex')
      throw new Error "Encryption key must be 32 bytes."

    if @hmacKey.length isnt 32
      console.log @hmacKey.toString('hex')
      throw new Error "HMAC Key must be 32 bytes"


  ###*
   * Decrypt an object
   * @param {String} type Can be either 'item', 'itemKey' or 'profileKey'
   * @param {String|Buffer} object The encrypted opdata object
   * @return {String} The decrypted object
  ###

  decrypt: (type, object) ->
    object = Crypto.toHex(object)

    if type isnt 'itemKey' and object[0...16].toUpperCase() isnt OPDATA01_HEADER
      console.error 'Not an opdata01 object'
      return false

    if type is 'itemKey'
      iv         = Crypto.toBuffer(object[0...32])
      ciphertext = Crypto.toBuffer(object[32...-64])

    else
      length     = Crypto.parseLittleEndian(object[16...32])
      iv         = Crypto.toBuffer(object[32...64])
      ciphertext = Crypto.toBuffer(object[64...-64])

    dataToHmac   = Crypto.toBuffer(object[0...-64])
    expectedHmac = object[-64..]

    # Verify HMAC
    objectHmac = Crypto.hmac(dataToHmac, @hmacKey, 256)
    if objectHmac isnt expectedHmac
      console.error 'Hmac does not match'
      return false

    # Decipher
    rawtext = Crypto.decrypt(ciphertext, @encryptionKey, iv, 'hex')

    if type isnt 'itemKey'
      plaintext = Crypto.unpad(length, rawtext)

    switch type

      when 'buffer'
        return Crypto.toBuffer(plaintext)

      when 'item'
        return Crypto.toBuffer(plaintext).toString('utf8')

      when 'itemKey'
        return [rawtext[0...64], rawtext[64..]]

      when 'profileKey'
        keys = Crypto.hash(plaintext, 512)
        return [keys[0...64], keys[64..]]


  ###*
   * Encrypt plaintext as object
   * @param {String} type Can be either 'item', 'itemKey' or 'profileKey'
   * @param {Buffer} plaintext The data to be encrypted
   * @return {Buffer} The encrypted opdata object
  ###

  encrypt: (type, plaintext) ->

    # Generate a random 16 byte IV
    iv = Crypto.randomBytes(16)

    # Pad the plaintext with the IV and block padding
    if type is 'itemKey'
      paddedtext = plaintext
    else
      paddedtext = Crypto.concat([iv, Crypto.pad(plaintext)])

    # Encrypt using AES 256 in cbc mode
    ciphertext = Crypto.encrypt(paddedtext, @encryptionKey, iv)

    # Header data
    if type is 'itemKey'
      dataToHmac = Crypto.concat([iv, ciphertext])
    else
      header = Crypto.toBuffer(OPDATA01_HEADER)
      endian = Crypto.stringifyLittleEndian(plaintext.length)
      endian = Crypto.toBuffer(endian)
      dataToHmac = Crypto.concat([header, endian, iv, ciphertext])

    # Generate a HMAC using SHA256
    hmac = Crypto.hmac(dataToHmac, @hmacKey, 256)
    hmac = Crypto.toBuffer(hmac)

    return Crypto.concat([dataToHmac, hmac])


module.exports = Opdata
