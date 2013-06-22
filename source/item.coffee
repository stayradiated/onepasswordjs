Crypto = require './crypto'
Opdata = require './opdata'

###*
 * @class An item stores data such as usernames and passwords.
###

class Item


  ###*
   * Create a new Item.
   * @param {Kecyhain} keychain The keychain to encrypt the item with.
   * @param {Object} data The data to add to the Item.
   * @return {Item} The item.
  ###
  @create: (keychain, data) =>

    timeNow = Math.floor Date.now() / 1000

    item = new Item keychain,
      uuid: Crypto.generateUuid()
      created: timeNow
      updated: timeNow
      category: '001'

    item.overview =
      title: data.title
      ainfo: data.username
      url: data.url
      URLS: [
        l: 'website'
        u: data.url
      ]

    item.details =
      fields: [
        type: 'T'
        name: 'username'
        value: data.username
        designation: 'username'
      ,
        type: 'P'
        name: 'password'
        value: data.password
        designation: 'password'
      ]
      notesPlain: data.notes or ''

    item.keys =
      encryption: Crypto.randomBytes(32)
      hmac: Crypto.randomBytes(32)

    item.encrypt('all')

    return item


  ###*
   * Create a new Item instance.
   * @constructor
   * @param {Object} [attrs] Any attributes to load into the item
  ###
  constructor: (@keychain, attrs) ->
    @keysUnlocked = false
    @detailsUnlocked = false
    @overviewUnlocked = false
    @encrypted = {}
    if attrs?
      for key, attr of attrs
        @[key] = attr


  ###*
   * Load attributes from the exported format
   * @param {Object} data Data to load
   * @return {this}
  ###
  load: (data) ->
    for key in ['category', 'created', 'fave', 'folder', 'tx', 'trashed', 'updated', 'uuid']
      if data[key]? then @[key] = data[key]

    # Convert to base64
    for key in ['d', 'hmac', 'k', 'o']
      continue unless data[key]?
      data[key] = Crypto.fromBase64(data[key])

    @hmac = data.hmac
    @encrypted.keys = data.k
    @encrypted.details = data.d
    @encrypted.overview = data.o

    return this


  ###*
   * Lock the item.
   * Deletes the unencrypted data.
  ###
  lock: (type) ->
    switch type
      when 'all'
        @lock('keys')
        @lock('details')
        @lock('overview')
        return this

      when 'keys'
        delete @keys
        keysUnlocked = false
        return this

      when 'details'
        delete @details
        detailsUnlocked = false
        return this

      when 'overview'
        delete @overview
        overviewUnlocked = false
        return this

  ###*
   * Decrypt the item data.
   * @param  {string} type The part of the item to unlock. Can be `all`, `keys`, `details` or `overview`.
  ###
  unlock: (type) ->
    switch type
      when 'all'
        @unlock('keys')
        @unlock('details')
        @unlock('overview')
        return this

      when 'keys'
        keys = @keychain.master.decrypt('itemKey', @encrypted.keys)
        @keys = new Opdata(keys[0], keys[1])
        @keysUnlocked = true
        return @keys

      when 'details'
        @unlock('keys') unless @keysUnlocked
        json = @keys.decrypt('item', @encrypted.details)
        @details = JSON.parse(json)
        @detailsUnlocked = true
        return @details

      when 'overview'
        json = @keychain.overview.decrypt('item', @encrypted.overview)
        @overview = JSON.parse(json)
        @overviewUnlocked = true
        return @overview


  ###*
   * Encrypt the item data.
   * @param  {string} type The part of the item to encrypt. Can be `all`, `keys`, `details` or `overview`.
  ###
  encrypt: (type) ->
    switch type
      when 'all'
        @encrypt('keys')
        @encrypt('details')
        @encrypt('overview')
        return this

      when 'keys'
        joined = Buffer.concat([@keys.encryption, @keys.hmac])
        @encrypted.keys = @keychain.master.encrypt('itemKey', joined)
        return this

      when 'details'
        @unlock('keys') unless @keysUnlocked
        json = JSON.stringify(@details)
        buffer = Crypto.toBuffer(json, 'utf8')
        @encrypted.details = @keys.encrypt('item', buffer)
        return this

      when 'overview'
        json = JSON.stringify(@overview)
        buffer = Crypto.toBuffer(json, 'utf8')
        @encrypted.overview = @keychain.overview.encrypt('item', buffer)
        return this


  ###*
   * Calculate the hmac of the item
   * TODO: Find out why it doesn't work...
   * @param {Buffer} key The master hmac key
   * @return {String} The hmac of the item encoded in hex
  ###
  calculateHmac: (key) ->
    dataToHmac = ""
    for element, data of @toJSON()
      continue if element is "hmac"
      dataToHmac += element + data

    dataToHmac = new Buffer(dataToHmac, 'utf8')
    hmac = Crypto.hmac(dataToHmac, key, 256, 'hex')

    console.log hmac
    console.log @hmac.toString('hex')


  ###*
   * Turn an item into a JSON object.
   * @return {Object} The JSON object.
  ###
  toJSON: ->
    category: @category
    created: @created
    d: @d?.toString('base64')
    # folder: ""
    hmac: @hmac?.toString('base64')
    k: @keys?.toString('base64')
    o: @o?.toString('base64')
    tx: @tx
    updated: @updated
    uuid: @uuid


  ###*
   * Check to see if an item matches a query. Used for filtering items.
   * @param {String} query The search query.
   * @return {Boolean} Whether or not the item matches the query.
  ###
  match: (query) =>
    query = query.toLowerCase()
    @overview.title.toLowerCase().match(query)


module.exports = Item