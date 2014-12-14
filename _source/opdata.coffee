# Javascript implementation of the Agile Bits Opdata Version 1 format
# http://learn.agilebits.com/1Password4/Security/keychain-design.html#opdata

# Dependencies
Crypto = require('./crypto')

# Constants
OPDATA_HEADER = new Buffer('6F70646174613031', 'hex')
OPDATA_HEADER_HEX = OPDATA_HEADER.toString('hex')

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
   * - object {buffer} : The encrypted opdata object
   * > string or buffer - The decrypted object
  ###

  decrypt: (type, buffer) ->

    if type isnt 'itemKey' and
    buffer[0..7].toString('hex') isnt OPDATA_HEADER_HEX
      console.error 'Not an opdata01 object'
      return false

    if type is 'itemKey'
      iv         = buffer[0..15]
      ciphertext = buffer[16..-33]

    else
      length     = Crypto.parseLittleEndian buffer[8..15]
      iv         = buffer[16..31]
      ciphertext = buffer[32..-33]

    dataToHmac   = buffer[0..-33]
    expectedHmac = buffer[-32..].toString('hex')

    # Verify HMAC
    hmac = Crypto.hmac(dataToHmac, @hmac, 256, 'hex')
    if hmac isnt expectedHmac
      # Hmac does not match, key and/or data is invalid
      return false

    # Decipher
    rawBuffer = Crypto.decrypt(ciphertext, @encryption, iv)
    
    # ItemKeys are not padded
    if type isnt 'itemKey'
      plaintext = Crypto.unpad(length, rawBuffer)
    
    # Depending on the type of data we are decrypting, 
    switch type

      when 'buffer'
        return plaintext

      when 'item'
        return plaintext.toString('utf8')

      when 'itemKey'
        return [ rawBuffer[0..31], rawBuffer[32..] ]

      when 'profileKey'
        # Profile keys are hashed with SHA512
        keys = Crypto.hash(plaintext, 512)
        return [ keys[0..31], keys[32..] ]


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
      paddedtext = Crypto.concat [ iv, Crypto.pad(plaintext) ]

    # Encrypt using AES 256 in CBC mode
    ciphertext = Crypto.encrypt( paddedtext, @encryption, iv )

    # Header data
    if type is 'itemKey'
      dataToHmac = Crypto.concat [ iv, ciphertext ]
    else
      header = OPDATA_HEADER
      endian = Crypto.toBuffer Crypto.littleEndian( plaintext.length )
      dataToHmac = Crypto.concat [ header, endian, iv, ciphertext ]

    # Generate a HMAC using SHA256
    hmac = Crypto.hmac( dataToHmac, @hmac, 256 )

    return Crypto.concat [ dataToHmac, hmac ]

module.exports = Opdata
