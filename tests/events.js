var assert = require('assert');
var Keychain = require('../js/keychain');
var keychain = new Keychain();

describe('Event Handler', function() {

  it('should listen for events', function(done) {
    keychain.on('simple', function() {
      done();
    });
    keychain._trigger('simple');
  });

  it('should pass data to events', function(done) {
    keychain.on('withData', function(data) {
      assert.equal(data, true);
      done();
    });
    keychain._trigger('withData', true);
  });

  it('should remove events', function() {
    keychain.on('remove', 'id', function() {
      throw new Error('Should not be fired');
    });
    keychain.off('remove', 'id');
    keychain._trigger('remove');
  });

  it('should remove all events when no ID is passed to off', function() {
    keychain.on('removeAll', 'id_1', function() {
      throw new Error('Should not be fired');
    });
    keychain.on('removeAll', 'id_2', function() {
      throw new Error('Should not be fired');
    });
    keychain.off('removeAll');
    keychain._trigger('removeAll');
  });

  it('should use .one() to listen for an event only once', function() {
    keychain.one('runOnce', function(data) {
      assert.equal(data, 1);
    });
    keychain._trigger('runOnce', 1);
    keychain._trigger('runOnce', 2);
  });

  it('should the ID of the event', function() {
    var id;
    id = keychain.on('d', 'id_1', function() {});
    assert.equal(id, 'id_1');
    id = keychain.one('d', 'id_2', function() {});
    assert.equal(id, 'id_2');
  });

});
