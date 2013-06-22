
###*
 * A collection of cryptographic functions.
 * The important ones (AES, SHA, HMAC ...) are all wrappers for the openssl
 * library built into Node.
###
#
nodeCrypto = require('crypto')

# Constants
BLOCKSIZE = 16

Crypto =

  ###*
   * Encrypt data using AES256 in CBC mode.
   * - plaintext {Buffer} : The data to encrypt.
   * - key {String|Buffer} : The key to encrypt with.
   * - iv {String|Buffer} : The initialization vector.
   * - [encoding] {string} : The format to return the encrypted data in.
   * > buffer
  ###
  encrypt: (plaintext, key, iv, encoding) ->
    iv = @toBuffer(iv)
    key = @toBuffer(key)
    cipher = nodeCrypto.createCipheriv('aes-256-cbc', key, iv)
    cipher.setAutoPadding(false)
    buffer = @concat [ cipher.update(plaintext), cipher.final() ]
    if encoding? then return buffer.toString(encoding)
    return buffer


  ###*
   * Decrypt encrypted data using AES256 in CBC mode
   * - ciphertext {String|Buffer} : The data to decipher. Length must be a
   *   multiple of the blocksize.
   * - key {String|Buffer} : The key to decipher with.
   * - iv {String|Buffer} : The initialization vector.
   * - [encoding] {String} : The format to return the decrypted contents in.
   * > buffer
  ###
  decrypt: (ciphertext, key, iv, encoding) ->
    iv = @toBuffer(iv)
    key = @toBuffer(key)
    ciphertext = @toBuffer(ciphertext)
    cipher = nodeCrypto.createDecipheriv('aes-256-cbc', key, iv)
    cipher.setAutoPadding(false)
    buffer = @concat [ cipher.update(ciphertext), cipher.final() ]
    if encoding? then return buffer.toString(encoding)
    return buffer


  ###*
   * Generate keys from password using PKDF2-HMAC-SHA512.
   * - password {String|Buffer} : The password.
   * - salt {String|Buffer} : The salt.
   * - [iterations=10000] {Number} : The numbers of iterations.
   * - [keysize=512] {Number} : The SHA algorithm to use.
   * > string
  ###
  pbkdf2: require('./crypto_pbkdf2')


  ###*
   * Cryptographically hash data using HMAC.
   * - data {String|Buffer} : The data to be hashed.
   * - key {String|Buffer} : The key to use with HMAC.
   * - keysize {Number} : The type of hash to use, e.g. 256 or 512.
   * - [encoding] {String} : Data encoding to return as. If left unspecified,
   *   it will return as a buffer.
   * > buffer
  ###
  hmac: (data, key, keysize, encoding) ->
    data = @toBuffer(data)
    key = @toBuffer(key)
    mode = 'sha' + keysize
    hmac = nodeCrypto.createHmac(mode, key)
    hmac.update(data)
    if encoding? then return hmac.digest(encoding)
    return hmac.digest()


  ###*
   * Create a hash digest of data.
   * - data {String|Buffer} : The data to hash.
   * - keysize {Number} : The type of hash to use, e.g. 256 or 512.
   * - [encoding] {String} : Data encoding to return as. If left unspecified,
   *   it will return as a buffer.
   * > buffer
  ###
  hash: (data, keysize, encoding) ->
    data = @toBuffer(data)
    mode = 'sha' + keysize
    hash = nodeCrypto.createHash(mode)
    hash.update(data)
    if encoding? then return hash.digest(encoding)
    return hash.digest()


  ###*
   * Prepend padding to data to make it fill the blocksize.
   * - data {Buffer} : The data to pad.
   * > buffer
  ###
  pad: (data) ->
    paddingLength = BLOCKSIZE - (data.length % BLOCKSIZE)
    padding = @randomBytes(paddingLength)
    return Buffer.concat [ padding, data ]


  ###*
   * Remove padding from text.
   * - plaintextLength {Number} : The length of the plaintext in bytes.
   * - data {String|Buffer} : The data to remove the padding from. Can be a
   *   hex string or a buffer.
   * > string
  ###
  unpad: (plaintextLength, data) ->
    data = @toHex(data)
    plaintextLength *= 2 # One byte is equal two hex characters
    return data[-plaintextLength..]


  ###*
   * Generates cryptographically strong pseudo-random data.
   * - length {Number} : How many bytes of data you need.
   * > buffer
  ###
  randomBytes: (length) ->
    return nodeCrypto.randomBytes(length)


  ###*
   * Generate a cryptographically strong pseudo-random number.
   * Very similar to Math.random() except it's more random.
   * > float - between 0 and 1
  ###
  randomValue: ->
    bytes = @randomBytes(4)
    hex = bytes.toString('hex')
    decimal = parseInt(hex, 16)
    return decimal * Math.pow(2, -32)


  ###*
   * Convert data to a Buffer
   * - data {String|Buffer} : The string to be converted.
   * - [encoding=hex] {String} : The format of the data to convert from.
   * > buffer
  ###
  toBuffer: (data, encoding='hex') ->
    if data instanceof Buffer then return data
    return new Buffer(data, encoding)


  ###*
   * Convert data to hex.
   * - data {String|Buffer} : The data to be converted.
   * > string
  ###
  toHex: (data) ->
    if data instanceof Buffer then return data.toString('hex')
    if typeof data is 'string' then return data
    throw new Error 'Input is not the correct type'


  ###*
   * Convert base64 to Buffer.
   * - data {String} : A base64 encoded string.
   * > buffer
  ###
  fromBase64: (data) ->
    return new Buffer(data, 'base64')


  ###*
   * Join an array of buffers together.
   * - buffers {Array} : An array of buffers.
   * > buffer
  ###
  concat: (buffers) ->
    Buffer.concat(buffers)


  ###*
   * Parse a litte endian number. Original JS version by Jim Rogers.
   * http://www.jimandkatrin.com/CodeBlog/post/Parse-a-little-endian.aspx
   * - hex {String} : The little endian number.
   * > {Number} - the little endian converted to a number.
  ###
  parseLittleEndian: (hex) ->
    result = 0
    pow = 0
    i = 0
    len = hex.length - 1
    while i < len
      result += parseInt(hex[i++..i++], 16) * Math.pow(2, pow)
      pow += 8
    return result


  ###*
   * Convert an integer into a little endian.
   * - number {Number} number The integer you want to convert.
   * - [pad=true] {Boolean} : Pad the little endian with zeroes.
   * > string
  ###
  stringifyLittleEndian: (number, pad=true) ->
    power = Math.floor((Math.log(number) / Math.LN2) / 8) * 8
    multiplier = Math.pow(2, power)
    value = Math.floor(number / multiplier)
    remainder = number % multiplier
    endian = ""
    if remainder > 255
      endian += @stringifyLittleEndian(remainder, false)
    else if power isnt 0
      endian += @dec2hex(remainder)
    endian += @dec2hex(value)
    if pad
      padding = 16 - endian.length
      endian += "0" for i in [0...padding] by 1
    return endian


  ###*
   * Turn a decimal into a hexadecimal.
   * - dec {Number} : The decimal.
   * > string
  ###
  dec2hex: (dec) ->
    hex = dec.toString(16)
    if hex.length < 2 then hex = "0" + hex
    return hex


  ###*
   * Convert a binary string into a hex string.
   * - binary {String} : The binary encoded string.
   * > string
  ###
  bin2hex: (binary) ->
    hex = ""
    for char in binary
      hex += char.charCodeAt(0).toString(16).replace(/^([\dA-F])$/i, "0$1")
    return hex


  ###*
   * Generate a uuid.
   * - param {Number} [length=32] The length of the UUID.
   * > string
  ###
  generateUuid: (length=32) ->
    length /= 2 # one byte is equal to two hex values
    return @randomBytes(length).toString('hex').toUpperCase(0)


module.exports = Crypto
