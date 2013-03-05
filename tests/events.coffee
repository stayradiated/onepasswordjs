assert = require 'assert'

Keychain = require '../src/keychain'
keychain = new Keychain()

describe 'Event Handler', ->

  it 'should listen for events', (done) ->
    keychain.on 'simple', ->
      done()
    keychain._trigger('simple')

  it 'should pass data to events', (done) ->
    keychain.on 'withData', (data) ->
      assert.equal(data, true)
      done()
    keychain._trigger('withData', true)

  it 'should remove events', ->
    keychain.on 'remove', 'id', ->
      throw new Error 'Should not be fired'
    keychain.off('remove', 'id')
    keychain._trigger('remove')

  it 'should remove all events when no ID is passed to off', ->
    keychain.on 'removeAll', 'id_1', ->
      throw new Error 'Should not be fired'
    keychain.on 'removeAll', 'id_2', ->
      throw new Error 'Should not be fired'
    keychain.off('removeAll')
    keychain._trigger('removeAll')

  it 'should use .one() to listen for an event only once', ->
    keychain.one 'runOnce', (data) ->
      assert.equal(data, 1)
    keychain._trigger('runOnce', 1)
    keychain._trigger('runOnce', 2)

  it 'should return the ID of the event', ->
    id = keychain.on 'returnId', 'id_1', ->
    assert.equal(id, 'id_1')
    id = keychain.one 'returnId', 'id_2', ->
    assert.equal(id, 'id_2')
