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

    keys =
      encryption: Crypto.randomBytes(32)
      hmac: Crypto.randomBytes(32)

    item.setItemKeys(keys)

    ###*
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

    ###

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
    for key in ['category', 'created', 'folder', 'tx', 'updated', 'uuid']
      if data[key]? then @[key] = data[key]

    for key in ['d', 'hmac', 'k', 'o']
      continue unless data[key]?
      @[key] = Crypto.fromBase64(data[key])

    return this


  ###*
   * Lock the item completely
  ###
  lock: ->
    @lockKeys()
    @lockDetails()
    @lockOverview()


  ###*
   * Decrypt the item encryption keys.
   * @param {Opdata} master The keychain master keys.
   * @return {Opdata} The item encryption keys.
  ###
  unlockKeys: ->
    keys = @keychain.master.decrypt('itemKey', @keys)
    @keys = new Opdata(keys[0], keys[1])
    @keysUnlocked = true
    return @keys


  ###*
   * Set the item encryption keys
   * @param {Opdata} master The keychain master keys.
   * @param {Object} keys The encryption and hmac keys.
   * @example
   *   item.setItemKeys(master, {
   *     encryption: encryptionKey,
   *     hmac: hmacKey
   *   })
  ###
  encryptKeys: (keys) ->
    joined = Buffer.concat([keys.encryption, keys.hmac])
    @keys = @kecyhain.master.encrypt('itemKey', joined)



  ###*
   * Decrypt the overview data of an item.
   * @param {Opdata} overviewKey An Opdata profile key made with the
   *                             keychain's overview keys. Used to decrypt
   *                             the overview data.
   * @return {Object} The overview data.
  ###
  unlockOverview: ->
    json = @keychain.overview.decrypt('item', @encrypted.overview)
    @overview = JSON.parse(json)
    @overviewUnlocked = true
    return @overview


  encryptOverview: ->
    json = JSON.stringify(@overview)
    buffer = Crypto.toBuffer(json, 'utf8')
    @encrypted.overview = @keychain.overview.encrypt('item', buffer)
    @overviewUnlocked = false
    return @encrypted.overview


  ###*
   * Decrypt the item details.
   * @param {Object} master The keychain's master keys. Used to decrypt the encryption keys.
   * @return {Object} The item details.
  ###
  unlockDetails: ->
    @decryptItemKeys() unless @keysUnlocked
    json = @keys.decrypt('item', @encrypted.details)
    @details = JSON.parse(json)
    @detailsUnlocked = true
    return @details


  encryptDetails: ->
    @decryptItemKeys() unless @keysUnlocked
    json = JSON.stringify(@details)
    buffer = Crypto.toBuffer(json, 'utf8')
    @encrypted.details = @keys.encrypt('item', buffer)
    @detailsUnlocked = false
    return @encrypted.details


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
    hmac = Crypto.hmac(dataToHmac, key, 256)

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


class Note extends Item
  category: "003"

  set: (data) ->
    @details.notesPlain = data
    @overview.notesPlain = data[0..79]



module.exports = Item
