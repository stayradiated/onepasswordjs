'use strict';

// Dependencies
var _ = require('lodash');
var Keychain = require('./keychain');
var Password = require('./password');
var Item = require('./item');

// Constants
var TYPE_SHARED_KEYCHAIN = 'Webkeys Shared Keychain';

var create = function () {
  var keychain, password;
  password = Password.random(30, 5, 5);
  keychain = Keychain.create(password);
};

var save = function (keychain, password) {
  return new Item({
    title: 'Shared Keychain',
    username: 'New Shared Keychain',
    password: password,
    url: keychain.keychainPath
  });
};

var findItems = Keychain.prototype.findItems;

Keychain.prototype.findItems = function (query, level) {
  var id, keychain, results;
  if (level == null) {
    level = 1;
  }
  if (level === 0) {
    return findItems(query);
  }
  results = (function () {
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

  detect: function (item) {
    if (item.type === TYPE_SHARED_KEYCHAIN) {
      item.hidden = true;
      return console.log(item);
    }
  },

  load: function (keychain) {
    var id = this.index;
    this.index += 1;
    this.all[id] = keychain;
    return id;
  },

  unload: function (id) {
    delete this.all[id];
  },

  list: function () {
    return _.reduce(this.all, function (result, value, key) {
      result.push({
        id: key,
        path: value.keychainPath,
      });

      return result;
    }, []);
  },

  get: function (id) {
    return this.all[id];
  }
};

module.exports = Keychain;
