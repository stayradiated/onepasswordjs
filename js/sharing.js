// Generated by CoffeeScript 1.6.2
(function() {
  var Item, Keychain, Password, TYPE_SHARED_KEYCHAIN, create, findItems, save;

  Keychain = require('./keychain');

  Password = require('./password');

  Item = require('./item');

  TYPE_SHARED_KEYCHAIN = 'Webkeys Shared Keychain';

  create = function() {
    var keychain, password;

    password = Password.random(30, 5, 5);
    return keychain = Keychain.create(password);
  };

  save = function(keychain, password) {
    var item;

    return item = new Item({
      title: 'Shared Keychain',
      username: 'New Shared Keychain',
      password: password,
      url: keychain.keychainPath
    });
  };

  findItems = Keychain.prototype.findItems;

  Keychain.prototype.findItems = function(query, level) {
    var id, keychain, results;

    if (level == null) {
      level = 1;
    }
    if (level === 0) {
      return findItems(query);
    }
    results = (function() {
      var _ref, _results;

      _ref = this.shared.all;
      _results = [];
      for (id in _ref) {
        keychain = _ref[id];
        _results.push(findItems(query));
      }
      return _results;
    }).call(this);
    return Array.prototype.concat.apply(results[0] || [], results.slice(1));
  };

  Keychain.prototype.shared = {
    all: {},
    index: 0,
    detect: function(item) {
      if (item.type === TYPE_SHARED_KEYCHAIN) {
        item.hidden = true;
        return console.log(item);
      }
    },
    load: function(keychain) {
      var id;

      id = this.index++;
      this.all[id] = keychain;
      return id;
    },
    unload: function(id) {
      return delete this.all[id];
    },
    list: function() {
      var id, keychain, _ref, _results;

      _ref = this.all;
      _results = [];
      for (id in _ref) {
        keychain = _ref[id];
        _results.push({
          id: id,
          path: keychain.keychainPath
        });
      }
      return _results;
    },
    get: function(id) {
      return this.all[id];
    }
  };

  module.exports = Keychain;

}).call(this);