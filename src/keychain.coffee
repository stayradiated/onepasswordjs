###*
 * @fileoverview Read and write 1Password 4 Cloud Keychain files. Based on the
 * documentation at {@link http://learn.agilebits.com/1Password4/Security/keychain-design.html Agile Bits}
 * and {@link https://github.com/Roguelazer/onepasswordpy OnePasswordPy}
 *
 * @author George Czabania
 * @version 0.1
###


# Load modules
fs = require 'fs'
Crypto = require './crypto'
Opdata = require './opdata'
Item = require './item'


# Constants
BAND_PREFIX = 'ld('
BAND_SUFFIX = ');'
PROFILE_PREFIX = 'var profile='
PROFILE_SUFFIX = ';'


###*
 * @class The Keychain stores all the items and profile data.
###

class Keychain


  ###*
   * Create a new keychain
   * @param  {String} password The master password for the keychain.
   * @param  {String} [hint] The master password hint.
   * @param  {String} [profileName=default] The name of the keychain profile.
   * @return {Keychain} Returns a new Keychain object
  ###

  @create: (password, hint, profileName='default') ->

    timeNow = Math.floor Date.now() / 1000

    keychain = new Keychain
      uuid: Crypto.generateUuid()
      salt: Crypto.randomBytes(16)
      createdAt: timeNow
      updatedAt: timeNow
      iterations: 20000
      profileName: profileName
      passwordHint: hint ? ''
      lastUpdatedBy: 'Dropbox'

    raw =
      master: Crypto.randomBytes(256)
      overview: Crypto.randomBytes(64)

    keys =
      master: Crypto.hash(raw.master, 512)
      overview: Crypto.hash(raw.overview, 512)

    superKey = keychain._deriveKeys(password)

    keychain.encrypted =
      masterKey: superKey.encrypt('profileKey', raw.master)
      overviewKey: superKey.encrypt('profileKey', raw.overview)

    keychain.master = new Opdata(keys.master[0...64], keys.master[64..])
    keychain.overview = new Opdata(keys.overview[0...64], keys.overview[64..])

    return keychain


  ###*
   * Constructs a new Keychain
   * @constructor
   * @param  {Object} [items={}] Load items
  ###
  constructor: (attrs) ->
    @AUTOLOCK_LENGTH = 1 * 60 * 1000 # 1 minute
    @profileName = 'default'
    @_events = {}
    @items = {}
    if attrs then @loadAttrs(attrs)


  ###*
   * Easy way to load data into a keychain
   * @param {Object} attrs The attributes you want to load
   * @return {this}
  ###
  loadAttrs: (attrs) ->
    for key, attr of attrs
      @[key] = attr
    return this


  ###*
   * Derive super keys from password using PBKDF2
   * @private
   * @param {String} password The master password.
   * @return {Opdata} The derived keys as an opdata object.
  ###
  _deriveKeys: (password) ->
    keys = Crypto.pbkdf2(password, @salt, @iterations)
    derived =
      encryption: Crypto.toBuffer(keys[0...64])
      hmac: Crypto.toBuffer(keys[64..])
    return new Opdata(derived.encryption, derived.hmac)


  ###*
   * Trigger an event.
   * @private
   * @param  {String} event  The event name
   * @param  {Splat}  [args] Any optional arguments you want to send with the
   *                         event.
  ###
  _trigger: (event, args...) ->
    return unless event of @_events
    for id, fn of @_events[event]
      continue unless typeof(fn) is 'function'
      if id[0..2] is "__"
        fnArgs = args.slice(0)
        fnArgs.unshift(id)
        fn(fnArgs...)
      else
        fn(args...)


  ###*
   * Listen for an event, and run a function when it is triggered.
   * @param  {String}   event  The event name
   * @param  {String}   [id]   The id of the listener
   * @param  {Function} fn     The function to run when the event is triggered
   * @param  {Boolean}  [_once] Run once, and then remove the listener
   * @return {String} The event id
  ###
  on: (event, id, fn, _once) ->
    @_events[event] ?= {index: 0}
    if typeof(id) is 'function'
      fn = id
      id = "__" + ++@_events[event].index
    if _once
       @_events[event][id] = (args...) =>
        fn(args...)
        @off(event, id)
    else
      @_events[event][id] = fn
    return id


  ###*
   * Unbind an event listener
   * @param {String} event The event name
   * @param {String} [id]  The id of the event. If left blank, then all events
   *                       will be removed
  ###
  off: (event, id) ->
    if id?
      delete @_events[event][id]
    else
      for id of @_events[event]
        delete @_events[event][id]


  ###*
   * Listen to an event, but only fire the listener once
   * @see this.on()
  ###
  one: (event, id, fn) ->
    @on(event, id, fn, true)


  ###*
   * Load data from a .cloudKeychain folder
   * @param  {String} filepath The filepath of the .cloudKeychain file
   * @throws {Error} If profile.js can't be found
  ###
  load: (@keychainPath) ->

    @profileFolder = "#{@keychainPath}/#{@profileName}"
    folderContents = fs.readdirSync(@profileFolder)
    profile = null
    folder = null
    bands = []
    attachments = []

    for filename in folderContents
      if filename is "profile.js"
        profile = "#{@profileFolder}/profile.js"
      else if filename is "folders.js"
        folders = "#{@profileFolder}/folders.js"
      else if filename.match(/^band_[0-9A-F]\.js$/)
        bands.push("#{@profileFolder}/#{filename}")
      else if filename.match(/^[0-9A-F]{32}_[0-9A-F]{32}\.attachment$/)
        attachments.push(filename)

    if profile?
      @loadProfile(profile)
    else
      throw new Error 'Couldn\'t find profile.js'

    if folders? then @loadFolders(folders)
    if bands.length > 0 then @loadBands(bands)
    if attachments.length > 0 then @loadAttachment(attachments)

    return this


  ###*
   * Load data from profile.js into keychain.
   * @param {String} filepath The path to the profile.js file.
   * @param {Boolean} [rawData=false] If set to true, 'filepath' will be considered the actual profile data to load from.
  ###
  loadProfile: (filepath, rawData) ->

    if rawData
      data = filepath
    else
      data = fs.readFileSync(filepath).toString()

    json = data[PROFILE_PREFIX.length...-PROFILE_SUFFIX.length]
    profile = JSON.parse(json)

    @loadAttrs
      uuid: profile.uuid
      salt: Crypto.fromBase64(profile.salt)
      createdAt: profile.createdAt
      updatedAt: profile.updatedAt
      iterations: profile.iterations
      profileName: profile.profileName
      passwordHint: profile.passwordHint
      lastUpdatedBy: profile.lastUpdatedBy

    @encrypted =
      masterKey: Crypto.fromBase64(profile.masterKey)
      overviewKey: Crypto.fromBase64(profile.overviewKey)

    return this


  ###*
   * Load folders
   * @param  {String} filepath The path to the folders.js file.
  ###
  loadFolders: (filepath) ->
    # TODO: Implements folders ...


  ###*
   * This loads the item data from a band file into the keychain.
   * @param  {Array} bands An array of filepaths to each band file
  ###
  loadBands: (bands) ->

    for filepath in bands

      # Load file
      band = fs.readFileSync(filepath).toString('utf8')
      band = band[BAND_PREFIX.length...-BAND_SUFFIX.length]
      band = JSON.parse(band)

      # Add items
      @addItem(item) for uuid, item of band

    return this


  ###*
   * Load attachments
   * @param  {Array} attachments An array of filepaths to each attachment file
  ###
  loadAttachment: (attachments) ->
    # TODO: Implement attachments ...


  ###*
   * Change the keychain master password. Since the derived keys and raw key data aren't stored, the current password must be supplied to decrypt this data again. Though slower, this is more secure than keeping this data in memory.
   * @param {string} currentPassword The current master password.
   * @param {string} newPassword The password to change to.
  ###
  changePassword: (currentPassword, newPassword) ->
    currentKey = @_deriveKeys(currentPassword)
    masterKey = currentKey.decrypt('buffer', @encrypted.masterKey)
    overviewKey = currentKey.decrypt('buffer', @encrypted.overviewKey)
    newKey = @_deriveKeys(newPassword)
    @encrypted.masterKey = newKey.encrypt('profileKey', masterKey)
    @encrypted.overviewKey = newKey.encrypt('profileKey', overviewKey)
    return this


  ###*
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
  ###
  unlock: (password) ->

    # Derive keys
    profileKey = @_deriveKeys(password)

    # Decrypt profile keys
    master = profileKey.decrypt('profileKey', @encrypted.masterKey)
    if not master.length
      console.error "Could not decrypt master key"
      return false

    overview = profileKey.decrypt('profileKey', @encrypted.overviewKey)
    if not overview.length
      console.error "Could not decrypt overview key"
      return false

    @master = new Opdata(master[0], master[1])
    @overview = new Opdata(overview[0], overview[1])

    # Decrypt overview data
    @eachItem (item) =>
      item.unlockOverview()

    @unlocked = true

    @rescheduleAutoLock()
    setTimeout (=> @_autolock()), 1000

    return this


  ###*
   * Lock the keychain. This discards all currently decrypted keys, overview
   * data and any decrypted item details.
   * @param {Boolean} autolock Whether the keychain was locked automatically.
  ###
  lock: (autolock) ->
    @_trigger 'lock', autolock
    @super = undefined
    @master = undefined
    @overview = undefined
    @items = {}
    @unlocked = false


  ###*
   * Reschedule when the keychain is locked. Should be called only when the
   * user performs an important action, such as unlocking the keychain,
   * selecting an item or copying a password, so that it doesn't lock when
   * they are using it.
  ###
  rescheduleAutoLock: ->
    @autoLockTime = Date.now() + @AUTOLOCK_LENGTH


  ###*
   * This is run every second, to check to see if the timer has expired. If it
   * has it then locks the keychain.
   * @private
  ###
  _autolock: =>
    return unless @unlocked
    now = Date.now()
    if now < @autoLockTime
      setTimeout @_autolock, 1000
      return
    @lock(true)


  ###*
   * Expose Item.create so you only have to include this one file
   * @param {Object} data Item data.
   * @return {Object} An item instance.
  ###
  createItem: (data) ->
    Item.create(this, data)


  ###*
   * Add an item to the keychain
   * @param {Object} item The item to add to the keychain
  ###
  addItem: (item) ->
    if not (item instanceof Item)
      item = new Item(this).load(item)
    @items[item.uuid] = item
    return this


  ###*
   * This returns an item with the matching UUID
   * @param  {String} uuid The UUID to find the Item of
   * @return {Item} The item matching the UUID
  ###
  getItem: (uuid) ->
    return @items[uuid]


  ###*
   * Search through all items
  ###
  findItems: (query) ->
    for uuid, item of @items
      if item.match(query) is null then continue
      item


  ###*
   * Loop through all the items in the keychain, and pass each one to a
   * function.
   * @param  {Function} fn The function to pass each item to
  ###
  eachItem: (fn) ->
    for uuid, item of @items
      fn(item)


  ###*
   * Generate the profile.js file
   * @return {String} The profile.js file
  ###
  exportProfile: ->
    data =
      lastUpdatedBy: @lastUpdatedBy
      updatedAt:     @updatedAt
      profileName:   @profileName
      salt:          @salt.toString('base64')
      passwordHint:  @passwordHint
      masterKey:     @encrypted.masterKey.toString('base64')
      iterations:    @iterations
      uuid:          @uuid
      overviewKey:   @encrypted.overviewKey.toString('base64')
      createdAt:     @createdAt
    PROFILE_PREFIX + JSON.stringify(data) + PROFILE_SUFFIX


  ###*
   * This exports all the items currently in the keychain into band files.
   * @return {Object} The band files
  ###
  exportBands: ->

    bands = {}

    for uuid, item of @items
      id = uuid[0...1]
      bands[id] ?= []
      bands[id].push(item)

    files = {}
    for id, items of bands
      data = {}
      for item in items
        data[item.uuid] = item.toJSON()
      data = BAND_PREFIX + JSON.stringify(data, null, 2) + BAND_SUFFIX
      files["band_#{id}.js"] = data

    return files


module.exports = Keychain
