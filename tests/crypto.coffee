assert = require 'assert'
Crypto = require '../keychain/crypto'

describe 'Crypto', ->

  ###*
   * ENCRYPTION
  ###

  mode = 'aes-256-cbc'
  encoding = 'hex'
  plaintext = new Buffer('0123456789ABCDEF')
  key = "f0fb2c2dea3b28bd08a60c7049a5f62c3388872b82160a005ad3eb00ff0f69f3"
  iv = "6993260ef345b11c7c53e4dac76326f9"
  ciphertext = '489aa87997c0b113e5000111c32a79cd'

  it 'should encrypt', ->
    encrypted = Crypto.encrypt(mode, plaintext, key, iv, encoding)
    assert.equal encrypted, ciphertext

  it 'should decrypt', ->
    decrypted = Crypto.decrypt(mode, ciphertext, key, iv)
    assert.equal decrypted.toString(), plaintext.toString()


  ###*
   * PBKDF2
  ###

  it 'should pbkdf2', ->
    password = 'password'
    salt = '0123456789ABCDEF'
    pbkdf2 = Crypto.pbkdf2(password, salt, 10000, 128)
    assert.equal pbkdf2, 'f119d9566f66c185d1616fc88d7edcb0'


  ###*
   * HMAC
  ###

  it 'should hmac', ->

  it 'should hash', ->

  it 'should pad', ->

  it 'should unpad', ->

  it 'should generate random data', ->