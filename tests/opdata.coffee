assert = require 'assert'
Opdata = require '../src/opdata'

# Sample keys from test.cloudkeychain
keys =
  encryption: new Buffer('1LsyuLnyAdLIYZbjBCJFNPDgIzh2NP+VZvh9Ty+8wBc=', 'base64')
  hmac: new Buffer('5zIgzmCRX3azU4kh2bziIXs0sU1WPf+JIHoOPyVySh8==', 'base64')

# Opdata object setup with keys
opdata = new Opdata(keys.encryption, keys.hmac)

describe 'Opdata', ->

  it 'should decrypt', ->

    profileKey = new Buffer('b3BkYXRhMDEAAQAAAAAAAJiPMcRoIjR5WmYGn8fiY48CHkjrdAcw/RuXv4WbqQ2pFlcrpZBNIAS+k4duUEhS8ech9BTzwRv5ZDRUAB07IjujOdm1WMZZh3qHZyslagGip/wUSUzFlTh0Xg0qV1n5Ke8t56lc+yLxH70CbPULbWebZVmYEsytQjTld2U+z4vumjqFMZOVzW2XEkxGE3SL11RybAE2gl/w+s2XuoSuIUVcJ8mHO7CYhTdivq64txTYgRgrZ10kBEun39yr/aCNM9rxyZC83DF7sTHXZkMXEqe/lQO5LSohUZHhhkX5XS7uEySmXEBNVyeIpFnDDqG0OUq9qaunNl7UZHNvCU9/ppksL2DsF+gfirAfgrXG+o65yzlADR2MfUje2KXF4084ZFRquBDSGdy7Z3yTo6cm1veOw4muObqnxR4CpLmKe/bI', 'base64')

    expectedKeys = [
      'b872f9d57294ec8ae056a41e1e905a88768a785de8c47662918eae92eeacef2b',
      'dcd674587d9cd6b72128fc50ecee9840200f27862b18c3767cbc6cd4deb709ed'
    ]

    assert.deepEqual expectedKeys, opdata.decrypt('profileKey', profileKey)


  it 'should encrypt', ->

    data = new Buffer("Hello World!")

    # Encrypt
    encrypted = opdata.encrypt('item', data).toString('hex')

    # Check that is opdata
    assert.equal encrypted[0..15], '6f70646174613031'
    assert.equal encrypted[16..31], '0c00000000000000'
    assert.equal encrypted.length, 192

    # Check decryption
    assert.equal opdata.decrypt('item', encrypted), "Hello World!"
