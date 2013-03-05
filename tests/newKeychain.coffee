# Run these tests using mocha
# mocha --compilers coffee:coffee-script tests.coffee

assert = require('assert')
fs = require('fs')

Keychain = require('../keychain/keychain')

describe 'Band', ->

  keychain = null

  it 'should create a new Keychain', ->
    keychain = Keychain.create('password', 'hint')

  it 'should create a new Item', ->
    data =
      title: 'Google Plus'
      username: 'username'
      password: 'password'
      url: 'plus.google.com'
      notes: 'Notes'

    item = Keychain.createItem(data, keychain.master, keychain.overview)
    keychain.addItem(item)

  it 'should export the band files', ->
    keychain.exportBands()
