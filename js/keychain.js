
/**
 * @fileoverview Read and write 1Password 4 Cloud Keychain files. Based on the
 * documentation at {@link http://learn.agilebits.com/1Password4/Security/keychain-design.html Agile Bits}
 * and {@link https://github.com/Roguelazer/onepasswordpy OnePasswordPy}
 *
 * @author George Czabania
 * @version 0.1
*/


(function() {
  var BAND_PREFIX, BAND_SUFFIX, Crypto, Item, Keychain, Opdata, PROFILE_PREFIX, PROFILE_SUFFIX, fs,
    __bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; },
    __slice = [].slice;

  fs = require('fs');

  Crypto = require('./crypto');

  Opdata = require('./opdata');

  Item = require('./item');

  BAND_PREFIX = 'ld(';

  BAND_SUFFIX = ');';

  PROFILE_PREFIX = 'var profile=';

  PROFILE_SUFFIX = ';';

  /**
   * @class The Keychain stores all the items and profile data.
  */


  Keychain = (function() {
    /**
     * Create a new keychain
     * @param  {String} password The master password for the keychain.
     * @param  {String} [hint] The master password hint.
     * @param  {String} [profileName=default] The name of the keychain profile.
     * @return {Keychain} Returns a new Keychain object
    */

    Keychain.create = function(password, hint, profileName) {
      var keychain, keys, raw, superKey, timeNow;
      if (profileName == null) {
        profileName = 'default';
      }
      timeNow = Math.floor(Date.now() / 1000);
      keychain = new Keychain({
        uuid: Crypto.generateUuid(),
        salt: Crypto.randomBytes(16),
        createdAt: timeNow,
        updatedAt: timeNow,
        iterations: 20000,
        profileName: profileName,
        passwordHint: hint != null ? hint : '',
        lastUpdatedBy: 'Dropbox'
      });
      raw = {
        master: Crypto.randomBytes(256),
        overview: Crypto.randomBytes(64)
      };
      keys = {
        master: Crypto.hash(raw.master, 'sha512'),
        overview: Crypto.hash(raw.overview, 'sha512')
      };
      superKey = keychain._deriveKeys(password);
      keychain.encrypted = {
        masterKey: superKey.encrypt('profileKey', raw.master),
        overviewKey: superKey.encrypt('profileKey', raw.overview)
      };
      keychain.master = {
        encryption: Crypto.toBuffer(keys.master.slice(0, 64)),
        hmac: Crypto.toBuffer(keys.master.slice(64))
      };
      keychain.overview = {
        encryption: Crypto.toBuffer(keys.overview.slice(0, 64)),
        hmac: Crypto.toBuffer(keys.overview.slice(64))
      };
      return keychain;
    };

    /**
     * Expose Item.create so you only have to include this one file
     * @type {Function}
    */


    Keychain.createItem = Item.create;

    /**
     * Constructs a new Keychain
     * @constructor
     * @param  {Object} [items={}] Load items
    */


    function Keychain(attrs) {
      this._autolock = __bind(this._autolock, this);      this.AUTOLOCK_LENGTH = 1 * 60 * 1000;
      this.profileName = 'default';
      this._events = {};
      this.items = {};
      if (attrs) {
        this.loadAttrs(attrs);
      }
    }

    /**
     * Easy way to load data into a keychain
     * @param {Object} attrs The attributes you want to load
     * @return {this}
    */


    Keychain.prototype.loadAttrs = function(attrs) {
      var attr, key;
      for (key in attrs) {
        attr = attrs[key];
        this[key] = attr;
      }
      return this;
    };

    /**
     * Derive super keys from password using PBKDF2
     * @private
     * @param {String} password The master password.
     * @return {Opdata} The derived keys as an opdata object.
    */


    Keychain.prototype._deriveKeys = function(password) {
      var keys;
      keys = Crypto.pbkdf2(password, this.salt, this.iterations);
      this["super"] = {
        encryption: Crypto.toBuffer(keys.slice(0, 64)),
        hmac: Crypto.toBuffer(keys.slice(64))
      };
      return new Opdata(this["super"].encryption, this["super"].hmac);
    };

    /**
     * Trigger an event.
     * @private
     * @param  {String} event  The event name
     * @param  {Splat}  [args] Any optional arguments you want to send with the
     *                         event.
    */


    Keychain.prototype._trigger = function() {
      var args, event, fn, fnArgs, id, _ref, _results;
      event = arguments[0], args = 2 <= arguments.length ? __slice.call(arguments, 1) : [];
      if (!(event in this._events)) {
        return;
      }
      _ref = this._events[event];
      _results = [];
      for (id in _ref) {
        fn = _ref[id];
        if (typeof fn !== 'function') {
          continue;
        }
        if (id.slice(0, 3) === "__") {
          fnArgs = args.slice(0);
          fnArgs.unshift(id);
          _results.push(fn.apply(null, fnArgs));
        } else {
          _results.push(fn.apply(null, args));
        }
      }
      return _results;
    };

    /**
     * Listen for an event, and run a function when it is triggered.
     * @param  {String}   event  The event name
     * @param  {String}   [id]   The id of the listener
     * @param  {Function} fn     The function to run when the event is triggered
     * @param  {Boolean}  [once] Run once, and then remove the listener
     * @return {String} The event id
    */


    Keychain.prototype.on = function(event, id, fn, once) {
      var _base, _ref,
        _this = this;
      if ((_ref = (_base = this._events)[event]) == null) {
        _base[event] = {
          index: 0
        };
      }
      if (typeof id === 'function') {
        fn = id;
        id = "__" + ++this._events[event].index;
      }
      if (once) {
        this._events[event][id] = function() {
          var args;
          args = 1 <= arguments.length ? __slice.call(arguments, 0) : [];
          fn.apply(null, args);
          return _this.off(event, id);
        };
      } else {
        this._events[event][id] = fn;
      }
      return id;
    };

    /**
     * Unbind an event listener
     * @param {String} event The event name
     * @param {String} [id]  The id of the event. If left blank, then all events
     *                       will be removed
    */


    Keychain.prototype.off = function(event, id) {
      var _results;
      if (id != null) {
        return delete this._events[event][id];
      } else {
        _results = [];
        for (id in this._events[event]) {
          _results.push(delete this._events[event][id]);
        }
        return _results;
      }
    };

    /**
     * Listen to an event, but only fire the listener once
     * @see this.on()
    */


    Keychain.prototype.one = function(event, id, fn) {
      return this.on(event, id, fn, true);
    };

    /**
     * Load data from a .cloudKeychain folder
     * @param  {String} filepath The filepath of the .cloudKeychain file
     * @throws {Error} If profile.js can't be found
    */


    Keychain.prototype.load = function(keychainPath) {
      var attachments, bands, filename, folder, folderContents, folders, profile, _i, _len;
      this.keychainPath = keychainPath;
      this.profileFolder = "" + this.keychainPath + "/" + this.profileName;
      folderContents = fs.readdirSync(this.profileFolder);
      profile = null;
      folder = null;
      bands = [];
      attachments = [];
      for (_i = 0, _len = folderContents.length; _i < _len; _i++) {
        filename = folderContents[_i];
        if (filename === "profile.js") {
          profile = "" + this.profileFolder + "/profile.js";
        } else if (filename === "folders.js") {
          folders = "" + this.profileFolder + "/folders.js";
        } else if (filename.match(/^band_[0-9A-F]\.js$/)) {
          bands.push("" + this.profileFolder + "/" + filename);
        } else if (filename.match(/^[0-9A-F]{32}_[0-9A-F]{32}\.attachment$/)) {
          attachments.push(filename);
        }
      }
      if (profile != null) {
        this.loadProfile(profile);
      } else {
        throw new Error('Couldn\'t find profile.js');
      }
      if (folders != null) {
        this.loadFolders(folders);
      }
      if (bands.length > 0) {
        this.loadBands(bands);
      }
      if (attachments.length > 0) {
        this.loadAttachment(attachments);
      }
      return this;
    };

    /**
     * Load data from profile.js into keychain.
     * @param  {String} filepath The path to the profile.js file.
    */


    Keychain.prototype.loadProfile = function(filepath) {
      var profile;
      profile = fs.readFileSync(filepath).toString();
      profile = profile.slice(PROFILE_PREFIX.length, -PROFILE_SUFFIX.length);
      profile = JSON.parse(profile);
      this.loadAttrs({
        uuid: profile.uuid,
        salt: Crypto.fromBase64(profile.salt),
        createdAt: profile.createdAt,
        updatedAt: profile.updatedAt,
        iterations: profile.iterations,
        profileName: profile.profileName,
        passwordHint: profile.passwordHint,
        lastUpdatedBy: profile.lastUpdatedBy
      });
      this.encrypted = {
        masterKey: Crypto.fromBase64(profile.masterKey),
        overviewKey: Crypto.fromBase64(profile.overviewKey)
      };
      return this;
    };

    /**
     * Load folders
     * @param  {String} filepath The path to the folders.js file.
    */


    Keychain.prototype.loadFolders = function(filepath) {};

    /**
     * This loads the item data from a band file into the keychain.
     * @param  {Array} bands An array of filepaths to each band file
    */


    Keychain.prototype.loadBands = function(bands) {
      var band, filepath, item, uuid, _i, _len;
      for (_i = 0, _len = bands.length; _i < _len; _i++) {
        filepath = bands[_i];
        band = fs.readFileSync(filepath).toString('utf8');
        band = band.slice(BAND_PREFIX.length, -BAND_SUFFIX.length);
        band = JSON.parse(band);
        for (uuid in band) {
          item = band[uuid];
          this.addItem(item);
        }
      }
      return this;
    };

    /**
     * Load attachments
     * @param  {Array} attachments An array of filepaths to each attachment file
    */


    Keychain.prototype.loadAttachment = function(attachments) {};

    /**
     * Runs the master password through PBKDF2 to derive the super keys, and then
     * decrypt the masterKey and overviewKey. The master password and super keys
     * are then forgotten as they are no longer needed and keeping them in memory
     * will only be a security risk.
     *
     * @param  {String} password The master password to unlock the keychain
     *                           with.
     * @return {Boolean} Whether or not the keychain was unlocked successfully.
     *                   Which is an easy way to see if the master password was
     *                   correct.
    */


    Keychain.prototype.unlock = function(password) {
      var master, overview, profileKey,
        _this = this;
      profileKey = this._deriveKeys(password);
      master = profileKey.decrypt('profileKey', this.encrypted.masterKey);
      if (!master.length) {
        console.error("Could not decrypt master key");
        return false;
      }
      overview = profileKey.decrypt('profileKey', this.encrypted.overviewKey);
      if (!overview.length) {
        console.error("Could not decrypt overview key");
        return false;
      }
      this.master = new Opdata(master[0], master[1]);
      this.overview = new Opdata(overview[0], overview[1]);
      this.eachItem(function(item) {
        return item.decryptOverview(_this.overview);
      });
      this.unlocked = true;
      this.rescheduleAutoLock();
      setTimeout((function() {
        return _this._autolock();
      }), 1000);
      return this;
    };

    /**
     * Lock the keychain. This discards all currently decrypted keys, overview
     * data and any decrypted item details.
     * @param {Boolean} autolock Whether the keychain was locked automatically.
    */


    Keychain.prototype.lock = function(autolock) {
      this._trigger('lock', autolock);
      this["super"] = void 0;
      this.master = void 0;
      this.overview = void 0;
      this.items = {};
      return this.unlocked = false;
    };

    /**
     * Reschedule when the keychain is locked. Should be called only when the
     * user performs an important action, such as unlocking the keychain,
     * selecting an item or copying a password, so that it doesn't lock when
     * they are using it.
    */


    Keychain.prototype.rescheduleAutoLock = function() {
      return this.autoLockTime = Date.now() + this.AUTOLOCK_LENGTH;
    };

    /**
     * This is run every second, to check to see if the timer has expired. If it
     * has it then locks the keychain.
     * @private
    */


    Keychain.prototype._autolock = function() {
      var now;
      if (!this.unlocked) {
        return;
      }
      now = Date.now();
      if (now < this.autoLockTime) {
        setTimeout(this._autolock, 1000);
        return;
      }
      return this.lock(true);
    };

    /**
     * Add an item to the keychain
     * @param {Object} item The item to add to the keychain
    */


    Keychain.prototype.addItem = function(item) {
      if (!(item instanceof Item)) {
        item = new Item().load(item);
      }
      this.items[item.uuid] = item;
      return this;
    };

    /**
     * Decrypt an item's details. The details are not saved to the item.
     * @param  {String} uuid The item UUID
     * @return {Object}      The items details
    */


    Keychain.prototype.decryptItem = function(uuid) {
      var item;
      item = this.getItem(uuid);
      return item.decryptDetails(this.master);
    };

    /**
     * Generate the profile.js file
     * @return {String} The profile.js file
    */


    Keychain.prototype.exportProfile = function() {
      var data;
      data = {
        lastUpdatedBy: this.lastUpdatedBy,
        updatedAt: this.updatedAt,
        profileName: this.profileName,
        salt: this.salt.toString('base64'),
        passwordHint: this.passwordHint,
        masterKey: this.encrypted.masterKey.toString('base64'),
        iterations: this.iterations,
        uuid: this.uuid,
        overviewKey: this.encrypted.overviewKey.toString('base64'),
        createdAt: this.createdAt
      };
      return PROFILE_PREFIX + JSON.stringify(data) + PROFILE_SUFFIX;
    };

    /**
     * This exports all the items currently in the keychain into band files.
     * @return {Object} The band files
    */


    Keychain.prototype.exportBands = function() {
      var bands, data, files, id, item, items, uuid, _i, _len, _ref, _ref1;
      bands = {};
      _ref = this.items;
      for (uuid in _ref) {
        item = _ref[uuid];
        id = uuid.slice(0, 1);
        if ((_ref1 = bands[id]) == null) {
          bands[id] = [];
        }
        bands[id].push(item);
      }
      files = {};
      for (id in bands) {
        items = bands[id];
        data = {};
        for (_i = 0, _len = items.length; _i < _len; _i++) {
          item = items[_i];
          data[item.uuid] = item.toJSON();
        }
        data = BAND_PREFIX + JSON.stringify(data, null, 2) + BAND_SUFFIX;
        files["band_" + id + ".js"] = data;
      }
      return files;
    };

    /**
     * This returns an item with the matching UUID
     * @param  {String} uuid The UUID to find the Item of
     * @return {Item} The item matching the UUID
    */


    Keychain.prototype.getItem = function(uuid) {
      return this.items[uuid];
    };

    /**
     * Search through all items
    */


    Keychain.prototype.findItem = function(query) {
      var item, uuid, _ref, _results;
      _ref = this.items;
      _results = [];
      for (uuid in _ref) {
        item = _ref[uuid];
        if (item.match(query) === null) {
          continue;
        }
        _results.push(item);
      }
      return _results;
    };

    /**
     * Loop through all the items in the keychain, and pass each one to a
     * function.
     * @param  {Function} fn The function to pass each item to
    */


    Keychain.prototype.eachItem = function(fn) {
      var item, uuid, _ref, _results;
      _ref = this.items;
      _results = [];
      for (uuid in _ref) {
        item = _ref[uuid];
        _results.push(fn(item));
      }
      return _results;
    };

    return Keychain;

  })();

  module.exports = Keychain;

}).call(this);
