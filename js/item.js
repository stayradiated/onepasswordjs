(function() {
  var Crypto, Item, Note, Opdata,
    __bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; },
    __hasProp = {}.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; };

  Crypto = require('./crypto');

  Opdata = require('./opdata');

  /**
   * @class An item stores data such as usernames and passwords.
  */


  Item = (function() {
    /**
     * Create a new Item.
     * @param {Object} data The data to add to the Item.
     * @param {Object} master The master encryption keys.
     * @param {Object} overview The overview encryption keys.
     * @return {Item} The item.
    */

    Item.create = function(data, master, overview) {
      var item, timeNow;
      timeNow = Math.floor(Date.now() / 1000);
      item = new Item({
        uuid: Crypto.generateUuid(),
        created: timeNow,
        updated: timeNow,
        category: '001'
      });
      item.overview = {
        title: data.title,
        ainfo: data.username,
        url: data.url,
        URLS: [
          {
            l: 'website',
            u: data.url
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
      /**
       *
       * TODO: Move into seperate encryption functions
       *
      
        keys.both = Crypto.concat([encryptionKey, hmacKey])
      
        detailsBuffer = Crypto.toBuffer(JSON.stringify(item.details), 'utf8')
        overviewBuffer = Crypto.toBuffer(JSON.stringify(item.overview), 'utf8')
      
        masterKey = new Opdata(master.encryption, master.hmac)
        overviewKey = new Opdata(overview.encryption, overview.hmac)
        itemKey = new Opdata(encryptionKey, hmacKey)
      
        item.k = masterKey.encrypt('itemKey', encryptionAndHmacKey)
        item.d = itemKey.encrypt('item', detailsBuffer)
        item.o = overviewKey.encrypt('item', overviewBuffer)
      */

      return item;
    };

    /**
     * Create a new Item instance.
     * @constructor
     * @param {Object} [attrs] Any attributes to load into the item
    */


    function Item(attrs) {
      this.match = __bind(this.match, this);
      var attr, key;
      if (attrs != null) {
        for (key in attrs) {
          attr = attrs[key];
          this[key] = attr;
        }
      }
    }

    /**
     * Load attributes from the exported format
     * @param {Object} data Data to load
     * @return {this}
    */


    Item.prototype.load = function(data) {
      var key, _i, _j, _len, _len1, _ref, _ref1;
      _ref = ['category', 'created', 'folder', 'tx', 'updated', 'uuid'];
      for (_i = 0, _len = _ref.length; _i < _len; _i++) {
        key = _ref[_i];
        if (data[key] != null) {
          this[key] = data[key];
        }
      }
      _ref1 = ['d', 'hmac', 'k', 'o'];
      for (_j = 0, _len1 = _ref1.length; _j < _len1; _j++) {
        key = _ref1[_j];
        if (data[key] == null) {
          continue;
        }
        this[key] = Crypto.fromBase64(data[key]);
      }
      return this;
    };

    /**
     * Decrypt the overview data of an item.
     * @param {Opdata} overviewKey An Opdata profile key made with the
     *                             keychain's overview keys. Used to decrypt
     *                             the overview data.
     * @return {Object} The overview data.
    */


    Item.prototype.decryptOverview = function(overviewKey) {
      var json;
      json = overviewKey.decrypt('item', this.o);
      return this.overview = JSON.parse(json);
    };

    Item.prototype.encryptOverview = function(overviewKey) {
      var buffer, json;
      json = JSON.stringify(this.overview);
      buffer = Crypto.toBuffer(json);
      this.o = overviewKey.encrypt('item', buffer);
      return this.o;
    };

    /**
     * Calculate the hmac of the item
     * TODO: Find out why it doesn't work...
     * @param {Buffer} key The master hmac key
     * @return {String} The hmac of the item encoded in hex
    */


    Item.prototype.calculateHmac = function(key) {
      var data, dataToHmac, element, hmac, _ref;
      dataToHmac = "";
      _ref = this.toJSON();
      for (element in _ref) {
        data = _ref[element];
        if (element === "hmac") {
          continue;
        }
        dataToHmac += element + data;
      }
      dataToHmac = new Buffer(dataToHmac, 'utf8');
      hmac = Crypto.hmac(dataToHmac, key, 'sha256');
      console.log(hmac);
      return console.log(this.hmac.toString('hex'));
    };

    /**
     * Decrypt the item details.
     * @param {Object} master The keychain's master keys. Used to decrypt
     *                        the encryption keys.
     * @return {Object} The item details.
    */


    Item.prototype.decryptDetails = function(masterKey) {
      var details, itemKey, keys;
      keys = masterKey.decrypt('itemKey', this.k);
      itemKey = new Opdata(keys[0], keys[1]);
      details = itemKey.decrypt('item', this.d);
      return JSON.parse(details);
    };

    Item.prototype.encryptDetails = function(masterKey, details) {
      var buffer, itemKey, json, keys;
      keys = masterKey.decrypt('itemKey', this.k);
      itemKey = new Opdata(keys[0], keys[1]);
      json = JSON.stringify(details);
      buffer = Crypto.toBuffer(json);
      this.d = itemKey.encrypt('item', buffer);
      return this.d;
    };

    /**
     * Turn an item into a JSON object.
     * @return {Object} The JSON object.
    */


    Item.prototype.toJSON = function() {
      var _ref;
      return {
        category: this.category,
        created: this.created,
        d: this.d.toString('base64'),
        hmac: (_ref = this.hmac) != null ? _ref.toString('base64') : void 0,
        k: this.k.toString('base64'),
        o: this.o.toString('base64'),
        tx: this.tx,
        updated: this.updated,
        uuid: this.uuid
      };
    };

    /**
     * Check to see if an item matches a query. Used for filtering items.
     * @param {String} query The search query.
     * @return {Boolean} Whether or not the item matches the query.
    */


    Item.prototype.match = function(query) {
      query = query.toLowerCase();
      return this.overview.title.toLowerCase().match(query);
    };

    return Item;

  }).call(this);

  Note = (function(_super) {

    __extends(Note, _super);

    function Note() {
      Note.__super__.constructor.apply(this, arguments);
    }

    Note.prototype.category = "003";

    Note.prototype.set = function(data) {
      this.details.notesPlain = data;
      return this.overview.notesPlain = data.slice(0, 80);
    };

    return Note;

  })(Item);

  module.exports = Item;

}).call(this);
