'use strict';

var _ = require('lodash');

var Crypto = require('./crypto');
var Opdata = require('./opdata');

/**
 * @class An item stores data such as usernames and passwords.
 */

/**
 * Create a new Item instance.
 * - [attrs] {object} : Any attributes to load into the item
 */

function Item (keychain, attrs) {
  this.keychain = keychain;

  this.match = this.match.bind(this);
  this.toJSON = this.toJSON.bind(this);

  this.keysUnlocked = false;
  this.detailsUnlocked = false;
  this.overviewUnlocked = false;
  this.encrypted = {};

  if (attrs !== null) {
    _.assign(this, attrs);
  }
}

/**
 * Create a new Item.
 * - keychain {kecyhain} : The keychain to encrypt the item with.
 * - data {object} : The data to add to the Item.
 * > item - the item.
 */
Item.create = function (keychain, data) {
  var timeNow = Math.floor(Date.now() / 1000);

  var item = new Item(keychain, {
    uuid:      Crypto.generateUuid(),
    created:   timeNow,
    updated:   timeNow,
    category:  '001'
  });

  item.overview = {
    title:  data.title,
    ainfo:  data.username,
    url:    data.url,
    URLS:   [
      {
        l:  'website',
        u:  data.url
      }
    ]
  };

  item.details = {
    fields: [
      {
        type: 'T',
        name: 'username',
        value: data.username,
        designation: 'username'
      }, {
        type: 'P',
        name: 'password',
        value: data.password,
        designation: 'password'
      }
    ],
    notesPlain: data.notes || ''
  };

  item.keys = {
    encryption: Crypto.randomBytes(32),
    hmac: Crypto.randomBytes(32)
  };

  item.encrypt('all');

  return item;
};


/**
 * Load attributes from the exported format
 * - data {object} : Data to load
 * > this
 */

Item.prototype.load = function (data) {

  // Only load valid attributes
  [
    'category', 'created', 'fave', 'folder', 'tx',
    'trashed', 'updated', 'uuid'
  ].forEach(function (key) {
    if (data.hasOwnProperty(key)) {
      this[key] = data[key];
    }
  }, this);

  // Convert to base64
  [
    'd', 'hmac', 'k', 'o'
  ].forEach(function (key) {
    if (data.hasOwnProperty(key)) {
      data[key] = Crypto.fromBase64(data[key]);
    }
  });

  this.hmac = data.hmac;
  this.encrypted.keys = data.k;
  this.encrypted.details = data.d;
  this.encrypted.overview = data.o;

  return this;
};


/**
 * Lock the item. Deletes the unencrypted data.
 * - type {string} : what to lock - all, keys, details or overview
 * > this
 */

Item.prototype.lock = function (type) {
  switch (type) {

    case 'all':
      this.lock('keys');
      this.lock('details');
      this.lock('overview');
      break;

    case 'keys':
      delete this.keys;
      this.keysUnlocked = false;
      break;

    case 'details':
      delete this.details;
      this.detailsUnlocked = false;
      break;

    case 'overview':
      delete this.overview;
      this.overviewUnlocked = false;
      break;
  }

  return this;
};


/**
 * Decrypt the item data.
 * - [type=all] {string} : The part of the item to unlock. Can be all, keys, 
 *   details or overview.
 * > this, keys, details, or overveiw
 */

Item.prototype.unlock = function (type) {
  if (! type) { type = 'all'; }

  var json;
  switch (type) {

    case 'all':
      this.unlock('keys');
      this.unlock('details');
      this.unlock('overview');
      return this;

    case 'keys':
      var keys = this.keychain.master.decrypt('itemKey', this.encrypted.keys);
      this.keys = new Opdata(new Buffer(keys[0], 'hex'), new Buffer(keys[1], 'hex'));
      this.keysUnlocked = true;
      return this.keys;

    case 'details':
      if (!this.keysUnlocked) { this.unlock('keys'); }
      json = this.keys.decrypt('item', this.encrypted.details);
      this.details = JSON.parse(json);
      this.detailsUnlocked = true;
      return this.details;

    case 'overview':
      json = this.keychain.overview.decrypt('item', this.encrypted.overview);
      this.overview = JSON.parse(json);
      this.overviewUnlocked = true;
      return this.overview;
  }
};


/**
 * Encrypt the item data.
 * - type {string} : The part of the item to encrypt. Can be all, keys,
 *   details or overview.
 * > this
 */

Item.prototype.encrypt = function (type) {
  if (! type) { type = 'all'; }

  var buffer;
  switch (type) {

    case 'all':
      this.encrypt('keys');
      this.encrypt('details');
      this.encrypt('overview');
      break;

    case 'keys':
      var joined = Buffer.concat([this.keys.encryption, this.keys.hmac]);
      this.encrypted.keys = this.keychain.master.encrypt('itemKey', joined);
      break;

    case 'details':
      if (!this.keysUnlocked) { this.unlock('keys'); }
      buffer = new Buffer(JSON.stringify(this.details));
      this.encrypted.details = this.keys.encrypt('item', buffer);
      break;

    case 'overview':
      buffer = new Buffer(JSON.stringify(this.overview));
      this.encrypted.overview = this.keychain.overview.encrypt('item', buffer);
  }
  return this;
};


/**
 * Calculate the hmac of the item
 * TODO: Find out why it doesn't work...
 * - key {Buffer} : The master hmac key
 * > string - The hmac of the item encoded in hex
 */

Item.prototype.calculateHmac = function (key) {
  console.log(this.toJSON());

  var json = this.toJSON();
  var data = _.reduce(this.toJSON(), function (result, value, key) {
    if (key === 'hmac') { return result; }
    return result + key + value;
  });
  var buffer = new Buffer(data);
  var hmac = Crypto.hmac(buffer, key, 256, 'hex');

  console.log(hmac);
  console.log(hmac.toString('hex'));

  return hmac.toString('hex');
};


Item.prototype.categoryName = function () {
  var list = {

    // Base Categories
    '001': 'Login',
    '002': 'Credit Card',
    '003': 'Secure Note',
    '004': 'Identity',
    '005': 'Generated Password',

    // Other Categories
    '100': 'Software License',
    '101': 'Bank Account',
    '102': 'Database',
    '103': 'Driver\'s License',
    '104': 'Outdoor License',
    '105': 'Membership',
    '106': 'Passport',
    '107': 'Reward Program',
    '108': 'Social Security Number',
    '109': 'Wireless Router',
    '110': 'Server',
    '111': 'Email Account'
  };

  return list[this.category];
};


/**
 * Turn an item into a JSON object.
 * > Object - the JSON object.
 */

Item.prototype.toJSON = function () {
  return {
    category:   this.category,
    created:    this.created,
    d:          this.encrypted.details.toString('base64'),
    // folder:  ''
    hmac:       this.hmac != null ? this.hmac.toString('base64') :  undefined,
    k:          this.encrypted.keys.toString('base64'),
    o:          this.encrypted.overview.toString('base64'),
    tx:         this.tx,
    updated:    this.updated,
    uuid:       this.uuid
  };
};


/**
 * Check to see if an item matches a query. Used for filtering items.
 * - query {string} : The search query.
 * > Boolean - Whether or not the item matches the query.
 */

Item.prototype.match = function (query) {
  var regex = new RegExp(query, 'i');
  return this.overview.title.match(regex);
};


module.exports = Item;
