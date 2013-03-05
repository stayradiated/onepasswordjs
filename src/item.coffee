Crypto = require './crypto'
Opdata = require './opdata'

###*
 * @class An item stores data such as usernames and passwords.
###

class Item


  ###*
   * Create a new Item.
   * @param {Object} data The data to add to the Item.
   * @param {Object} master The master encryption keys.
   * @param {Object} overview The overview encryption keys.
   * @return {Item} The item.
  ###
  @create: (data, master, overview) =>

    timeNow = Math.floor Date.now() / 1000

    item = new Item
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
  constructor: (attrs) ->
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
   * Decrypt the overview data of an item.
   * @param {Opdata} overviewKey An Opdata profile key made with the
   *                             keychain's overview keys. Used to decrypt
   *                             the overview data.
   * @return {Object} The overview data.
  ###
  decryptOverview: (overviewKey) ->
    json = overviewKey.decrypt('item', @o)
    @overview = JSON.parse(json)


  encryptOverview: (overviewKey) ->
    json = JSON.stringify(@overview)
    buffer = Crypto.toBuffer(json)
    @o = overviewKey.encrypt('item', buffer)
    return @o


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
   * Decrypt the item details.
   * @param {Object} master The keychain's master keys. Used to decrypt the encryption keys.
   * @return {Object} The item details.
  ###
  decryptDetails: (masterKey) ->

    # Decrypt item keys
    keys = masterKey.decrypt('itemKey', @k)
    itemKey = new Opdata(keys[0], keys[1])

    # Decrypt item details
    details = itemKey.decrypt('item', @d)
    return JSON.parse(details)


  encryptDetails: (masterKey, details) ->

    keys = masterKey.decrypt('itemKey', @k)
    itemKey = new Opdata(keys[0], keys[1])

    json = JSON.stringify(details)
    buffer = Crypto.toBuffer(json)
    @d = itemKey.encrypt('item', buffer)
    return @d


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
    k: @k?.toString('base64')
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
