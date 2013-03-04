assert = require 'assert'
Crypto = require '../keychain/crypto'

describe 'Crypto', ->

  ###*
   * ENCRYPTION
  ###

  encoding = 'hex'
  plaintext = new Buffer('0123456789ABCDEF')
  key = "f0fb2c2dea3b28bd08a60c7049a5f62c3388872b82160a005ad3eb00ff0f69f3"
  iv = "6993260ef345b11c7c53e4dac76326f9"
  ciphertext = '489aa87997c0b113e5000111c32a79cd'

  it 'should encrypt', ->
    encrypted = Crypto.encrypt(plaintext, key, iv, encoding)
    assert.equal encrypted, ciphertext

  it 'should decrypt', ->
    decrypted = Crypto.decrypt(ciphertext, key, iv)
    assert.equal decrypted.toString(), plaintext.toString()


  ###*
   * PBKDF2
  ###

  it 'should pbkdf2', ->
    password = 'password'
    salt = '0123456789ABCDEF'
    pbkdf2 = Crypto.pbkdf2(password, salt, 10000, 512)
    assert.equal pbkdf2, 'f119d9566f66c185d1616fc88d7edcb003abd7bcef4e1dcf3fbc628cb9acface5fdda2f14320661feddf6ebda3e10f313ba7c2a12e532050668d229d67f9f6a0'


  ###*
   * HMAC
  ###

  it 'should hmac', ->
    hash = Crypto.hmac(
      'bdd50cd25aacbab410ce7b8b9dcb97b17340be26793632fc80983d3bf525e0d7',
      '1bb1cc1d4f43b0a632ffe2ab1520f44df989ad33b2d82635d600aae8e05f5b4e',
      256
    )
    assert.equal hash, '83f6ba83b23b2efa853a9d695fb5e349d4ea65360478fec345ee14b70c5f4699'

  ###*
   * HASH
  ###

  it 'should hash', ->
    hash = Crypto.hash('f04a1b185b1bfb92c73ecd430642b59332190b94e7ea0b5a9c65490032dcf253', 256)
    assert.equal hash, 'bf1b0a9672b18dd90790fbe044155b1750e978fa832237ff4fb615c5e235034f'


  ###*
   * Padding
  ###

  it 'should pad', ->
    input = new Buffer('000000', 'hex')
    padding = Crypto.pad(input)
    assert.equal padding.length, 16
    assert.equal padding.toString('hex')[-6..], '000000'

  it 'should unpad', ->
    input = new Buffer('00000000000000001122334455667788', 'hex')
    unpadded = Crypto.unpad(8, input)
    assert.equal unpadded.length, 16
    assert.equal unpadded.toString('hex'), '1122334455667788'


  ###*
   * Random Data
  ###

  it 'should generate random data', ->
    bytes = Crypto.randomBytes(64)
    assert.equal bytes.length, 64


  ###*
   * Encoding
  ###

  it 'should convert data to a Buffer', ->
    data = Crypto.randomBytes(64)
    hex = data.toString('hex')
    buffer = Crypto.toBuffer(hex, 'hex')
    assert.equal (buffer instanceof Buffer), true

  it 'should convert data to Hex', ->
    data = Crypto.randomBytes(64)
    hex = Crypto.toHex(data)
    assert.equal data.toString('hex'), hex

  it 'should convert data from Base64', ->
    data = Crypto.randomBytes(64)
    buffer = Crypto.fromBase64 data.toString('base64')
    assert.equal buffer.toString('hex'), data.toString('hex')

  it 'should concat buffers', ->
    a = Crypto.randomBytes(16)
    b = Crypto.randomBytes(16)
    c = Crypto.randomBytes(16)
    d = Crypto.concat([a, b, c])
    assert.equal d.length, 48
    assert.equal d.slice(0, 16).toString(), a.toString()
    assert.equal d.slice(16, 32).toString(), b.toString()
    assert.equal d.slice(32, 48).toString(), c.toString()

  it 'should read and write little endian numbers', ->
    numbers =
      8192: "0020000000000000"
      256: "0001000000000000"
      64: "4000000000000000"
    for val, endian of numbers
      assert.equal Crypto.parseLittleEndian(endian), val
      assert.equal Crypto.stringifyLittleEndian(val), endian

  it 'should convert decimal to hex', ->
    numbers =
      0: "00"
      60: "3c"
      128: "80"
      160: "a0"
      255: "ff"
    for dec, hex of numbers
      dec = parseInt(dec, 10)
      assert.equal Crypto.dec2hex(dec), hex

  it 'should convert binary to hex', ->
    hex = 'bada55c0ffee'
    binary = 'ºÚUÀÿî'
    assert.equal Crypto.bin2hex(binary), hex


  it 'should generate UUIDS', ->
    uuid = Crypto.generateUuid()
    assert.equal uuid.length, 32
