nodeCrypto = require('crypto')

# Constants
BLOCKSIZE = 16


###*
 * @class Crypto
###

Crypto =

  ###*
   * Encipher data using AES256 in CBC mode
   * @param {Buffer} plaintext The data to encrypt.
   * @param {String|Buffer} key The key to encrypt with. Can be a Buffer or
   *                            hex encoded string.
   * @param {String|Buffer} iv The IV. Can be a Buffer or hex encoded string.
   * @param {string} [encoding=Buffer] The format to return the encrypted
   *                                   data at.
   * @return {Buffer|String} The encrypted data.
  ###
  encrypt: (plaintext, key, iv, encoding) ->
    iv = @toBuffer(iv)
    key = @toBuffer(key)
    cipher = nodeCrypto.createCipheriv('aes-256-cbc', key, iv)
    # Don't use the default padding
    cipher.setAutoPadding(false)
    binary = cipher.update(plaintext) + cipher.final()
    buffer = new Buffer(binary, 'binary')
    if encoding?
      return buffer.toString(encoding)
    else
      return buffer


  ###*
   * Decipher encrypted data using AES256 in CBC mode
   * @param {String|Buffer} ciphertext The data to decipher. Must be a
   *                                   multiple of the blocksize.
   * @param {String|Buffer} key The key to decipher the data with.
   * @param {String|Buffer} iv The initialization vector to use.
   * @param {String} [encoding=Buffer] The format to return the decrypted
   *                                   contents as.
   * @return {Buffer|String} The decrypted contents.
  ###
  decrypt: (ciphertext, key, iv, encoding) ->
    iv = @toBuffer(iv)
    key = @toBuffer(key)
    ciphertext = @toBuffer(ciphertext)
    cipher = nodeCrypto.createDecipheriv('aes-256-cbc', key, iv)
    # Don't use the default padding
    cipher.setAutoPadding(false)
    binary = cipher.update(ciphertext) + cipher.final()
    buffer = new Buffer(binary, 'binary')
    if encoding?
      return buffer.toString(encoding)
    else
      return buffer


  ###*
   * Generate keys from password using PKDF2-HMAC-SHA512.
   * @param {String|Buffer} password The password.
   * @param {String|Buffer} salt The salt.
   * @param {Number} [iterations=10000] The numbers of iterations.
   * @param {Number} [keysize=512] The SHA algorithm to use.
   * @return {String} Returns the derived key encoded as hex.
  ###
  pbkdf2: require('./crypto_pbkdf2')


  ###*
   * Cryptographically hash data using HMAC.
   * @param {String|Buffer} data The data to be hashed.
   * @param {String|Buffer} key The key to use with HMAC.
   * @param {string} mode The type of hash to use, such as sha1, sha256 or
   *                      sha512.
   * @return {String} The hmac digest encoded as hex.
  ###
  hmac: (data, key, keysize) ->
    data = @toBuffer(data)
    key = @toBuffer(key)
    mode = "sha#{keysize}"
    hmac = nodeCrypto.createHmac(mode, key)
    hmac.update(data)
    return hmac.digest('hex')


  ###*
   * Create a hash digest of data.
   * @param {String|Buffer} data The data to hash.
   * @param {String} mode The type of hash to use, such as sha1, sha256, or
   *                      sha512.
   * @return {String} The hash digest encoded as hex.
  ###
  hash: (data, keysize) ->
    data = @toBuffer(data)
    mode = "sha#{keysize}"
    hash = nodeCrypto.createHash(mode)
    hash.update(data)
    return hash.digest('hex')


  ###*
   * Prepend padding to data to make it fill the blocksize.
   * @param {Buffer} data The data to pad.
   * @return {Buffer} The data with padding added.
  ###
  pad: (data) ->
    bytesToPad = BLOCKSIZE - (data.length % BLOCKSIZE)
    padding = @randomBytes(bytesToPad)
    return Buffer.concat([padding, data])


  ###*
   * Remove padding from text.
   * @param {Numbers} plaintextLength The length of the plaintext in bytes.
   * @param {String|Buffer} data The data to remove the padding as a string
   *                             encoded as hex or a buffer.
   * @return {String} The data with the padding removed encoded as hex.
  ###
  unpad: (plaintextLength, data) ->
    data = @toHex(data)
    # One byte uses two hex characters
    plaintextLength *= 2
    return data[-plaintextLength..]


  ###*
   * Generates cryptographically strong pseudo-random data.
   * @param {Numbers} length How many bytes of data you want.
   * @return {Buffer} The random data as a Buffer.
  ###
  randomBytes: (length) ->
    return nodeCrypto.randomBytes(length)


  ###*
   * Convert data to a Buffer
   * @param {String|Buffer} data The data to be converted. If a string, must
   *                             be encoded as hex.
   * @param {String} [encoding=hex] The format of the data to convert.
   * @return {Buffer} The data as a Buffer
  ###
  toBuffer: (data, encoding='hex') ->
    if data instanceof Buffer then return data
    return new Buffer(data, encoding)


  ###*
   * Convert data to hex.
   * @param {String|Buffer} data The data to be converted.
   * @return {String} The data encoded as hex.
  ###
  toHex: (data) ->
    if data instanceof Buffer then return data.toString('hex')
    return data


  ###*
   * Convert base64 to Buffer.
   * @param {String} data A base64 encoded string.
   * @return {Buffer} The base64 string as a Buffer.
  ###
  fromBase64: (data) ->
    return new Buffer(data, 'base64')


  ###*
   * Join an array of buffers together.
   * @param {Array} buffers An array of buffers.
   * @return {Buffer} The buffers joined together.
  ###
  concat: (buffers) ->
    Buffer.concat(buffers)


  ###*
   * Parse a litte endian number.
   * @author Jim Rogers {@link http://www.jimandkatrin.com/CodeBlog/post/Parse-a-little-endian.aspx}
   * @param {String} hex The little endian number.
   * @return {Number} The little endian converted to a number.
  ###
  parseLittleEndian: (hex) ->
    result = 0
    pow = 0
    while hex.length > 0
      result += parseInt(hex.substring(0, 2), 16) * Math.pow(2, pow)
      hex = hex.substring(2, hex.length)
      pow += 8
    return result


  ###*
   * Convert an integer into a little endian.
   * @param {Number} number The integer you want to convert.
   * @param {Boolean} [pad=true] Pad the little endian with zeroes.
   * @return {String} The little endian.
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
   * @param {Number} dec The decimal.
   * @return {String} The hexadecimal.
  ###
  dec2hex: (dec) ->
    hex = dec.toString(16)
    if hex.length < 2 then hex = "0" + hex
    return hex


  ###*
   * Convert a binary string into a hex string.
   * @param {String} binary The binary encoded string.
   * @return {String} The hex encoded string.
  ###
  bin2hex: (binary) ->
    hex = ""
    for char in binary
      hex += char.charCodeAt(0).toString(16).replace(/^([\dA-F])$/i, "0$1")
    return hex


  ###*
   * Generate a uuid.
   * @param {Number} [length=32] The length of the UUID.
   * @return {String} The UUID.
  ###
  generateUuid: (length=32) ->
    length /= 2
    return @randomBytes(length).toString('hex').toUpperCase(0)


module.exports = Crypto
