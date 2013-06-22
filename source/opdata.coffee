# Javascript implementation of the Agile Bits Opdata Version 1 format
# http://learn.agilebits.com/1Password4/Security/keychain-design.html#opdata

# Dependencies
Crypto = require('./crypto')

# Constants
OPDATA_HEADER = '6F70646174613031'

class Opdata

  ###
   * Opdata object. Construct a new instance with the keys and then use it to
   * encrypt and decrypt data.
   * - encryption {buffer} : The encryption key
   * - hmac {buffer} : The hmac key
  ###

  constructor: (@encryption, @hmac) ->

    if @encryption.length isnt 32
      throw new Error "Encryption key must be 32 bytes."

    if @hmac.length isnt 32
      throw new Error "HMAC Key must be 32 bytes"


  ###
   * Decrypt an object
   * - type {string} : Can be either buffer, item, itemKey or profileKey
   * - object {string or buffer} : The encrypted opdata object
   * > string or buffer - The decrypted object
  ###

  decrypt: (type, object) ->

    if object not instanceof Buffer
      console.log object

    object = Crypto.toHex(object)

    if type isnt 'itemKey' and object[0..15].toUpperCase() isnt OPDATA_HEADER
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
    objectHmac = Crypto.hmac(dataToHmac, @hmac, 256, 'hex')
    if objectHmac isnt expectedHmac
      # Hmac does not match, key and/or data is invalid
      return false

    # Decipher
    rawBuffer = Crypto.decrypt(ciphertext, @encryption, iv)
    
    # ItemKeys are not padded
    if type isnt 'itemKey'
      plaintext = Crypto.unpad(length, rawBuffer)

    switch type

      when 'buffer'
        return plaintext

      when 'item'
        return plaintext.toString('utf8')

      when 'itemKey'
        return [rawBuffer[0..31], rawBuffer[32..]]

      when 'profileKey'
        keys = Crypto.hash(plaintext, 512)
        return [keys[0..31],keys[32..]]


  ###
   * Encrypt plaintext as object
   * - type {String} : Can be either 'item', 'itemKey' or 'profileKey'
   * - plaintext {Buffer} : The data to be encrypted
   * > buffer - the encrypted opdata object
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
    ciphertext = Crypto.encrypt(paddedtext, @encryption, iv)

    # Header data
    if type is 'itemKey'
      dataToHmac = Crypto.concat([iv, ciphertext])
    else
      header = Crypto.toBuffer(OPDATA_HEADER)
      endian = Crypto.stringifyLittleEndian(plaintext.length)
      endian = Crypto.toBuffer(endian)
      dataToHmac = Crypto.concat([header, endian, iv, ciphertext])

    # Generate a HMAC using SHA256
    hmac = Crypto.hmac(dataToHmac, @hmac, 256)

    return Crypto.concat([dataToHmac, hmac])

module.exports = Opdata
