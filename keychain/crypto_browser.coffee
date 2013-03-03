###*
 * @fileOverview A collection of cryptographic functions that work in most browsers.
###

Gibberish = require('../libs/gibberish-aes')
jsSHA = require('../libs/sha')
sjcl = require('../libs/sjcl')


# Constants
BLOCKSIZE = 16


Crypto =


  ###*
   * Encipher data
   * @param {Buffer} plaintext The data to encrypt.
   * @param {String|Buffer} key The key to encrypt with. Can be a Buffer or hex encoded string.
   * @param {String|Buffer} iv The IV. Can be a Buffer or hex encoded string.
   * @param {string} [encoding=buffer] The format to return the encrypted data at.
   * @return {String} The encrypted data.
  ###
  encrypt: (plaintext, key, iv, encoding="buffer") ->
    key = @toBuffer(key)
    iv = @toBuffer(iv)
    blocks = Gibberish.rawEncrypt(plaintext, key, iv)
    base64 = Gibberish.Base64.encode(blocks, false)
    if encoding is 'base64' then return base64
    ciphertext = Gibberish.Base64.decode(base64)
    if encoding is 'hex' then return Gibberish.a2h(ciphertext)
    if encoding is 'buffer'
      return ciphertext
    else
      throw new Error("Encoding not supported")


  ###*
   * Decipher encrypted data.
   * @param {String|Buffer} ciphertext The data to decipher. Must be a multiple of the blocksize.
   * @param {String|Buffer} key The key to decipher the data with.
   * @param {String|Buffer} iv The initialization vector to use.
   * @param {String} [encoding=buffer] The format to return the decrypted contents as.
   * @return {Buffer|String} The decrypted contents.
  ###
  decrypt: (ciphertext, key, iv, encoding="buffer") ->
    iv = @toBuffer(iv)
    key = @toBuffer(key)
    ciphertext = @toBuffer(ciphertext)
    binary = Gibberish.rawDecrypt(ciphertext, key, iv, true)
    hex = @bin2hex(binary)
    if encoding is 'hex' then return hex
    bytes = Gibberish.h2a(hex)
    if encoding is 'base64' then return Gibberish.Base64.encode(bytes)
    if encoding is "buffer"
      return bytes
    else
      throw new Error("Encoding now supported")


  ###*
   * Generate keys from password using PKDF2-HMAC-SHA512.
   * @param {String} password The password.
   * @param {String|Buffer} salt The salt.
   * @param {Number} [iterations=10000] The numbers of iterations.
   * @param {Numbers} [keySize=512] The length of the derived key in bits.
   * @return {String} Returns the derived key encoded as hex.
  ###
  pbkdf2: (password, salt, iterations=10000, keySize=512) ->

    self = this

    class hmac

      constructor: (key) ->
        @key = sjcl.codec.bytes.fromBits(key)

      encrypt: (sjclArray) ->
        byteArray = sjcl.codec.bytes.fromBits(sjclArray)
        hex = self.hmac(byteArray, @key, keySize)
        bits = sjcl.codec.hex.toBits(hex)
        return bits

    salt = sjcl.codec.hex.toBits(@toHex(salt))
    bits = sjcl.misc.pbkdf2(password, salt, iterations, keySize, hmac)
    return sjcl.codec.hex.fromBits(bits)


  ###*
   * Cryptographically hash data using HMAC.
   * @param {String|Buffer} data The data to be hashed.
   * @param {String|Buffer} key The key to use with HMAC.
   * @param {Number} [keysize=512] The keysize for the hash function.
   * @return {String} The hmac digest encoded as hex.
  ###
  hmac: (data, key, keysize=512) ->
    data = @toHex(data)
    key = @toHex(key)
    mode = "SHA-#{keysize}"
    input = new jsSHA(data, "HEX")
    return input.getHMAC(key, "HEX", mode, "HEX")


  ###*
   * Create a hash digest of data.
   * @param {String|Buffer} data The data to hash.
   * @param {Number} [keysize=512] The keysize for the hash function.
   * @return {String} The hash digest encoded as hex.
  ###
  hash: (data, keysize=512) ->
    data = @toHex(data)
    mode = "SHA-#{keysize}"
    input = new jsSHA(data, "HEX")
    return input.getHash(mode, "HEX")


  ###*
   * Prepend padding to data to make it fill the blocksize.
   * @param {Buffer} data The data to pad.
   * @return {Buffer} The data with padding added.
  ###
  pad: (data) ->
    bytesToPad = BLOCKSIZE - (data.length % BLOCKSIZE)
    padding = @randomBytes(bytesToPad)
    return @concat([padding, data])


  ###*
   * Remove padding from text.
   * @param {Numbers} plaintextLength The length of the plaintext in bytes.
   * @param {String|Buffer} data The data to remove the padding as a string encoded as hex or a buffer.
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
    array = new Uint8Array(length)
    window.crypto.getRandomValues(array)
    byte for byte in array


  ###*
   * Convert data to a Buffer
   * @param {String|Buffer} data The data to be converted. If a string, must be encoded as hex.
   * @param {String} [encoding=hex] The format of the data to convert.
   * @return {Buffer} The data as a Buffer
  ###
  toBuffer: (data, encoding='hex') ->
    if Array.isArray(data) then return data
    switch encoding
      when 'base64'
        return Gibberish.base64.decode(data)
      when 'hex'
        return Gibberish.h2a(data)
      when 'utf8'
        return Gibberish.s2a(data)
      else
        throw new Error("Encoding not supported")


  ###*
   * Convert data to hex.
   * @param {String|Buffer} data The data to be converted.
   * @return {String} The data encoded as hex.
  ###
  toHex: (data) ->
    if Array.isArray(data)
      return Gibberish.a2h(data)
    return data


  ###*
   * Convert base64 to Buffer.
   * @param {String} data A base64 encoded string.
   * @return {Buffer} The base64 string as a Buffer.
  ###
  fromBase64: (data) ->
    Gibberish.Base64.decode(data)


  ###*
   * Join an array of buffers together.
   * @param {Array} buffers An array of buffers.
   * @return {Buffer} The buffers joined together.
  ###
  concat: (buffers) ->
    Array::concat.apply(buffers[0], buffers[1..])


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
    bytes = @randomBytes(length)
    hex = @toHex(bytes).toUpperCase()


module.exports = Crypto
