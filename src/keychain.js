'use strict';

/**
 * Read and write 1Password 4 Cloud Keychain files. Based on the documentation
 * at http://learn.agilebits.com/1Password4/Security/keychain-design.html
 * and https://github.com/Roguelazer/onepasswordpy
 */

// Dependencies
var fs = require('fs');
var _ = require('lodash');
var EventEmitter = require('events').EventEmitter;

var Crypto = require('./crypto');
var Opdata = require('./opdata');
var Item = require('./item');

// Constants
var BAND_PREFIX = 'ld(';
var BAND_SUFFIX = ');';
var PROFILE_PREFIX = 'var profile=';
var PROFILE_SUFFIX = ';';

/**
 * Constructs a new Keychain
 * - [attrs] {object} : Load items
 */

function Keychain (attrs) {
  this.profileName = 'default';
  this.items = {};
  this.unlocked = false;
  this.event = new EventEmitter();

  if (attrs) {
    _.assign(this, attrs);
  }
}


/**
 * Create a new keychain
 * - password  {string} : The master password for the keychain.
 * - [options] {object} : Extra options for the keychain, such as the hint
 *   and number of iterations
 * > Keychain - a new Keychain object
 */
Keychain.create = function (password, options) {
  var currentTime = Math.floor(Date.now() / 1000);

  var defaults = {
    uuid:           Crypto.generateUuid(),
    salt:           Crypto.randomBytes(16),
    createdAt:      currentTime,
    updatedAt:      currentTime,
    iterations:     10000,
    profileName:    'default',
    passwordHint:   '',
    lastUpdatedBy:  'Dropbox'
  };

  // Merge user specified settings with default options
  _.defaults(options, (defaults || {}));

  var keychain = new Keychain(options);

  var raw = {
    master: Crypto.randomBytes(256),
    overview: Crypto.randomBytes(64)
  };

  var superKey = keychain._deriveKeys(password);

  keychain.encrypted = {
    masterKey: superKey.encrypt('profileKey', raw.master),
    overviewKey: superKey.encrypt('profileKey', raw.overview)
  };

  var keys = {
    master: Crypto.hash(raw.master, 512),
    overview: Crypto.hash(raw.overview, 512)
  };

  keychain.master = new Opdata(
    keys.master.slice(0, 32), // master encryption key
    keys.master.slice(32)     // master hmac key
  );

  keychain.overview = new Opdata(
    keys.overview.slice(0, 32), // overview encryption key
    keys.overview.slice(32)     // overview hmac key
  );

  return keychain;
};


/**
 * Derive the 'super' keys from password using PBKDF2
 * - {string} password The master password.
 * > Opdata - the derived keys.
 */

Keychain.prototype._deriveKeys = function (password) {
  var keys = Crypto.pbkdf2(password, this.salt, this.iterations);
  return new Opdata(
    keys.slice(0, 32), // encryption key
    keys.slice(32)     // hmac key
  );
};


/*
 * Load data from a .cloudKeychain folder
 * - filepath {string} : The filepath of the .cloudKeychain file
 * - [callback] {function} : Called when the keychain has loaded
 * ! if profile.js can't be found
 * > this
 */

Keychain.prototype.load = function (keychainPath, callback) {
  if (callback == null) { callback = _.noop; }

  this.keychainPath = keychainPath;
  this.profileFolder = this.keychainPath + '/' + this.profileName;

  var self = this;
  fs.readdir(this.profileFolder, function (err, folderContents) {
    if (err != null) {
      callback(err);
      return;
    }

    var profile = null;
    var folders = null;
    var bands = [];
    var attachments = [];

    for (var i = 0, len = folderContents.length; i < len; i += 1) {
      var filename = folderContents[i];

      if (filename === 'profile.js') {
        profile = self.profileFolder + '/profile.js';
      } else if (filename === 'folders.js') {
        folders = self.profileFolder + '/folders.js';
      } else if (filename.match(/^band_[0-9A-F]\.js$/)) {
        bands.push(self.profileFolder + '/' + filename);
      } else if (filename.match(/^[0-9A-F]{32}_[0-9A-F]{32}\.attachment$/)) {
        attachments.push(filename);
      }
    }

    if (profile != null) {
      self.loadProfile(profile);
    } else {
      callback(new Error('Couldn\'t find profile.js'));
    }

    if (folders != null) { self.loadFolders(folders); }
    if (bands.length > 0) { self.loadBands(bands); }
    if (attachments.length > 0) { self.loadAttachment(attachments); }

    callback(null);
  });

  return this;
};


/**
 * Load data from profile.js into keychain.
 * - filepath {string} : The path to the profile.js file.
 * - [rawData=false] {boolean} : If set to true, 'filepath' will be
 *   considered the actual profile data to load from.
 * > this
 */

Keychain.prototype.loadProfile = function (filepath, rawData) {
  var data = rawData ? filepath : fs.readFileSync(filepath).toString();

  var json = data.slice(PROFILE_PREFIX.length, -PROFILE_SUFFIX.length);
  var profile = JSON.parse(json);

  _.assign(this, {
    uuid:           profile.uuid,
    salt:           Crypto.fromBase64(profile.salt),
    createdAt:      profile.createdAt,
    updatedAt:      profile.updatedAt,
    iterations:     profile.iterations,
    profileName:    profile.profileName,
    passwordHint:   profile.passwordHint,
    lastUpdatedBy:  profile.lastUpdatedBy
  });

  this.encrypted = {
    masterKey: Crypto.fromBase64(profile.masterKey),
    overviewKey: Crypto.fromBase64(profile.overviewKey)
  };

  return this;
};


/**
 * Load folders
 * - filepath {string} : The path to the folders.js file.
 */

Keychain.prototype.loadFolders = function (filepath) {
  // TODO: Implement folders ...
};


/**
 * This loads the item data from a band file into the keychain.
 * - bands {array} : An array of filepaths to each band file
 * > this
 */

Keychain.prototype.loadBands = function (bands) {

  for (var i = 0, len = bands.length; i < len; i += 1) {
    var filepath = bands[i];

    // Load file
    var band = fs.readFileSync(filepath).toString('utf8');
    band = band.slice(BAND_PREFIX.length, -BAND_SUFFIX.length);
    band = JSON.parse(band);

    // Add items
    for (var uuid in band) {
      this.addItem(band[uuid]);
    }
  }

  return this;
};


/**
 * Load attachments
 * - attachments {Array} : An array of filepaths to each attachment file
 */

Keychain.prototype.loadAttachment = function (attachments) {
  // TODO: Implement attachments ...
};


/**
 * Change the keychain master password. Since the derived keys and raw key
 * data aren't stored, the current password must be supplied to decrypt this
 * data again. Though slower, this is more secure than keeping this data in
 * memory.
 * - currentPassword {string} : The current master password.
 * - newPassword {string} : The password to change to.
 * > this
 */

Keychain.prototype.changePassword = function (currentPassword, newPassword) {
  var currentKey = this._deriveKeys(currentPassword);
  var masterKey = currentKey.decrypt('buffer', this.encrypted.masterKey);
  var overviewKey = currentKey.decrypt('buffer', this.encrypted.overviewKey);
  var newKey = this._deriveKeys(newPassword);
  this.encrypted.masterKey = newKey.encrypt('profileKey', masterKey);
  this.encrypted.overviewKey = newKey.encrypt('profileKey', overviewKey);
  return this;
};


/**
 * Runs the master password through PBKDF2 to derive the super keys, and then
 * decrypt the masterKey and overviewKey. The master password and super keys
 * are then forgotten as they are no longer needed and keeping them in memory
 * will only be a security risk.
 * Use @unlocked to check if it was the right password.
 * - password {string} : The master password to unlock the keychain with.
 * > this
 */

Keychain.prototype.unlock = function (password) {

  if (this.unlocked === true) {
    console.log('Keychain already unlocked...');
    return this;
  }

  // Derive keys
  var profileKey = this._deriveKeys(password);

  // Decrypt master key
  var master = profileKey.decrypt('profileKey', this.encrypted.masterKey);
  if (! master.length) {
    console.error('Could not decrypt master key');
    this.unlocked = false;
    return this;
  }

  // Decrypt overview key
  var overview = profileKey.decrypt('profileKey', this.encrypted.overviewKey);
  if (! overview.length) {
    console.error('Could not decrypt overview key');
    this.unlocked = false;
    return this;
  }

  // Store keys
  this.master = new Opdata(master[0], master[1]);
  this.overview = new Opdata(overview[0], overview[1]);

  // Decrypt each item
  _.forIn(this.items, function (item) {
    return item.unlock('overview');
  });

  // Unlock has been successful
  this.unlocked = true;
  this.event.emit('unlock');

  return this;
};


/**
 * Lock the keychain. This discards all currently decrypted keys, overview
 * data and any decrypted item details.
 * > this
 */

Keychain.prototype.lock = function () {
  delete this["super"];
  delete this.master;
  delete this.overview;

  _.forIn(this.items, function (item) {
    item.lock('all');
  });

  this.unlocked = false;
  return this;
};

/**
 * Expose Item.create so you only have to include this one file
 * - data {Object} : Item data.
 * > object - An item instance.
 */

Keychain.prototype.createItem = function (data) {
  return Item.create(this, data);
};


/**
 * Add an item to the keychain
 * - item {Object} : The item to add to the keychain
 * > this
 */

Keychain.prototype.addItem = function (item) {
  if (!(item instanceof Item)) {
    item = new Item(this).load(item);
  }
  this.items[item.uuid] = item;
  return this;
};


/**
 * This returns an item with the matching UUID
 * - uuid {string} : The UUID to find the Item of
 * > item
 */

Keychain.prototype.getItem = function (uuid) {
  return this.items[uuid];
};


/**
 * Search through all items, does not include deleted items
 * - query {string} - the search query
 * > array - items that match the query
 */

Keychain.prototype.findItems = function (query) {
  var items = [];
  for (var uuid in this.items) {
    var item = this.items[uuid];
    if ((! item.trashed) && item.match(query) !== null) {
      items.push(item);
    }
  }
  return items;
};


/**
 * Generate the profile.js file
 * > string - the profile.js file contents as json
 */

Keychain.prototype.exportProfile = function () {
  var data = {
    lastUpdatedBy:  this.lastUpdatedBy,
    updatedAt:      this.updatedAt,
    profileName:    this.profileName,
    salt:           this.salt.toString('base64'),
    passwordHint:   this.passwordHint,
    masterKey:      this.encrypted.masterKey.toString('base64'),
    iterations:     this.iterations,
    uuid:           this.uuid,
    overviewKey:    this.encrypted.overviewKey.toString('base64'),
    createdAt:      this.createdAt
  };
  return PROFILE_PREFIX + JSON.stringify(data) + PROFILE_SUFFIX;
};


/**
 * This exports all the items currently in the keychain into band files.
 * > object - the band files as { filename: contents }
 */

Keychain.prototype.exportBands = function () {
  var bands = {};
  var id;

  // Sort items into groups based on the first char of its UUID
  for (var uuid in this.items) {
    id = uuid.slice(0, 1);
    if (! bands.hasOwnProperty(id)) {
      bands[id] = [];
    }
    bands[id].push(this.items[uuid]);
  }

  var files = {};

  // generate band files and filenames
  for (id in bands) {
    var items = bands[id];
    var data = {};
    for (var i = 0, len = items.length; i < len; i += 1) {
      var item = items[i];
      data[item.uuid] = item.toJSON();
    }
    data = BAND_PREFIX + JSON.stringify(data, null, 2) + BAND_SUFFIX;
    files["band_" + id + ".js"] = data;
  }

  return files;
};

module.exports = Keychain;
