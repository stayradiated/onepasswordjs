var assert = require('assert');
var fs = require('fs');
var Keychain = require('../js/keychain');

describe('Create Keychain', function() {
  var keychain;

  it('should create a new Keychain', function() {
    keychain = Keychain.create('password', 'hint');
  });

  it('should create a new Item', function() {
    var data = {
      title: 'Google Plus',
      username: 'username',
      password: 'password',
      url: 'plus.google.com',
      notes: 'Notes'
    };
    var item = keychain.createItem(data);
    keychain.addItem(item);
    assert.equal(keychain.getItem(item.uuid).overview.title, data.title)
  });

  it('should export the band files', function() {
    keychain.exportBands();
  });

});

describe('Existing Keychain', function() {
  var keychain;

  it('should open a keychain file', function() {
    keychain = new Keychain();
    keychain.load('./data/tests.cloudkeychain');
  });

  it('should unlock the keychain', function() {
    keychain.unlock('fred');
  });

  it('should decrypt an item', function() {
    var uuid = Object.keys(keychain.items)[0];
    var item = keychain.getItem(uuid);
    item.unlock('details')
  });

  it('should edit and save an item', function() {
    var uuid = Object.keys(keychain.items)[1];
    var item = keychain.getItem(uuid);
    item.unlock('details');
    item.details.title = 'item title';
    item.encrypt('details').lock('details');
    assert.equal(item.details, undefined);
    item.unlock('details');
    assert.equal(item.details.title, 'item title');
    item.lock('all');
    assert.equal(item.keys, undefined);
  });

  it('should change the password', function() {
    keychain.changePassword('fred', 'george');
    var profile = keychain.exportProfile();
    var newKeychain = new Keychain();
    newKeychain.loadProfile(profile, true);
    newKeychain.unlock('george');
  });

  it('should lock the keychain', function() {
    keychain.lock();
    assert.equal(keychain["super"], void 0);
    assert.equal(keychain.master, void 0);
    assert.equal(keychain.overview, void 0);
    assert.deepEqual(keychain.items, {});
  });

});
