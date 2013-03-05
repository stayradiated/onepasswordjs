# Run these tests using mocha
# mocha --compilers coffee:coffee-script tests.coffee

assert = require('assert')
fs = require('fs')

describe 'Keychain', ->

  Keychain = require('../src/keychain')
  keychain = null

  it 'should open a keychain file', ->
    keychain = new Keychain()
    keychain.load('./data/tests.cloudkeychain')

  it 'should unlock the keychain', ->
    keychain.unlock('fred')

  it 'should decrypt an item', ->
    uuid = Object.keys(keychain.items)[0]
    details = keychain.decryptItem(uuid)

  it 'should lock the keychain', ->
    keychain.lock()
    assert.equal keychain.super, undefined
    assert.equal keychain.master, undefined
    assert.equal keychain.overview, undefined
    assert.deepEqual keychain.items, {}

