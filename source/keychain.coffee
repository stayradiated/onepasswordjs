
###*
 * Read and write 1Password 4 Cloud Keychain files. Based on the documentation
 * at http://learn.agilebits.com/1Password4/Security/keychain-design.html
 * and https://github.com/Roguelazer/onepasswordpy
###


# Dependencies
fs = require 'fs'
{EventEmitter} = require 'events'
Crypto = require './crypto'
Opdata = require './opdata'
Item = require './item'


# Constants
BAND_PREFIX = 'ld('
BAND_SUFFIX = ');'
PROFILE_PREFIX = 'var profile='
PROFILE_SUFFIX = ';'


class Keychain


  ###*
   * Create a new keychain
   * - password  {string} : The master password for the keychain.
   * - [settings] {object} : Extra options for the keychain, such as the hint
   *   and number of iterations
   * > Keychain - a new Keychain object
  ###

  @create: (password, settings={}) ->

    currentTime = Math.floor(Date.now() / 1000)

    options =
      uuid: Crypto.generateUuid()
      salt: Crypto.randomBytes(16)
      createdAt: currentTime
      updatedAt: currentTime
      iterations: 2500
      profileName: 'default'
      passwordHint: ''
      lastUpdatedBy: 'Dropbox'

    # Merge user specified settings with default options
    for key in options
      if settings.hasOwnProperty(key)
        options[key] = settings[key]

    keychain = new Keychain(options)

    raw =
      master: Crypto.randomBytes(256)
      overview: Crypto.randomBytes(64)

    superKey = keychain._deriveKeys(password)

    keychain.encrypted =
      masterKey: superKey.encrypt('profileKey', raw.master)
      overviewKey: superKey.encrypt('profileKey', raw.overview)

    keys =
      master: Crypto.hash(raw.master, 512)
      overview: Crypto.hash(raw.overview, 512)

    keychain.master = new Opdata(
      keys.master[0..31] # master encryption key
      keys.master[32..]  # master hmac key
    )
    keychain.overview = new Opdata(
      keys.overview[0..31] # overview encryption key
      keys.overview[32..]  # overview hmac key
    )

    return keychain


  ###*
   * Constructs a new Keychain
   * - [attrs] {object} : Load items
  ###
  constructor: (attrs) ->
    @AUTOLOCK_LENGTH = 1 * 60 * 1000 # 1 minute
    @profileName = 'default'
    @items = {}
    @unlocked = false
    @event = new EventEmitter()
    if attrs then @loadAttrs(attrs)


  ###*
   * Easy way to load data into a keychain
   * - {object} attrs The attributes you want to load
   * > this - so it can be chained
  ###
  loadAttrs: (attrs) ->
    @[key] = attr for key, attr of attrs
    return this


  ###*
   * Derive the 'super' keys from password using PBKDF2
   * - {string} password The master password.
   * > Opdata - the derived keys.
  ###
  _deriveKeys: (password) ->
    keys = Crypto.pbkdf2( password, @salt, @iterations )
    return new Opdata(
      keys[0..31] # encryption key
      keys[32..]  # hmac key
    )


  ###
   * Load data from a .cloudKeychain folder
   * - filepath {string} : The filepath of the .cloudKeychain file
   * ! if profile.js can't be found
   * > this
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
   * - filepath {string} : The path to the profile.js file.
   * - [rawData=false] {boolean} : If set to true, 'filepath' will be
   *   considered the actual profile data to load from.
   * > this
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
   * - filepath {string} : The path to the folders.js file.
  ###
  loadFolders: (filepath) ->
    # TODO: Implements folders ...


  ###*
   * This loads the item data from a band file into the keychain.
   * - bands {array} : An array of filepaths to each band file
   * > this
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
   * - attachments {Array} : An array of filepaths to each attachment file
  ###
  loadAttachment: (attachments) ->
    # TODO: Implement attachments ...


  ###*
   * Change the keychain master password. Since the derived keys and raw key
   * data aren't stored, the current password must be supplied to decrypt this
   * data again. Though slower, this is more secure than keeping this data in
   * memory.
   * - currentPassword {string} : The current master password.
   * - newPassword {string} : The password to change to.
   * > this
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
   * Use @unlocked to check if it was the right password.
   * - password {string} : The master password to unlock the keychain with.
   * > this
  ###
  unlock: (password) ->

    if @unlocked is true
      console.log 'Keychain already unlocked...'
      return this

    # Derive keys
    profileKey = @_deriveKeys(password)

    # Decrypt master key
    master = profileKey.decrypt('profileKey', @encrypted.masterKey)
    if not master.length
      console.error 'Could not decrypt master key'
      @unlocked = false
      return this

    # Decrypt overview key
    overview = profileKey.decrypt('profileKey', @encrypted.overviewKey)
    if not overview.length
      console.error 'Could not decrypt overview key'
      @unlocked = false
      return this

    # Store keys
    @master = new Opdata(master[0], master[1])
    @overview = new Opdata(overview[0], overview[1])

    # Decrypt overview data
    @eachItem (item) -> item.unlock('overview')

    # Unlock has been successful
    @unlocked = true
    @event.emit('unlock')

    # Start autolock timer
    @rescheduleAutoLock()
    setTimeout (=> @_autolock()), 1000

    return this


  ###*
   * Lock the keychain. This discards all currently decrypted keys, overview
   * data and any decrypted item details.
   * - autolock {Boolean} : Whether the keychain was locked automatically.
   * > this
  ###
  lock: (autolock) ->
    @event.emit('lock:before', autolock)
    @super = undefined
    @master = undefined
    @overview = undefined
    @items = {}
    @unlocked = false
    @event.emit('lock:after', autolock)
    return this


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
   * - data {Object} : Item data.
   * > object - An item instance.
  ###
  createItem: (data) ->
    Item.create(this, data)


  ###*
   * Add an item to the keychain
   * - item {Object} : The item to add to the keychain
   * > this
  ###
  addItem: (item) ->
    if not (item instanceof Item)
      item = new Item(this).load(item)
    @items[item.uuid] = item
    return this


  ###*
   * This returns an item with the matching UUID
   * - uuid {string} : The UUID to find the Item of
   * > item
  ###
  getItem: (uuid) ->
    return @items[uuid]


  ###*
   * Search through all items, does not include deleted items
   * - query {string} - the search query
   * > array - items that match the query
  ###
  findItems: (query) ->
    items = []
    for uuid, item of @items
      if item.trashed then continue
      if item.match(query) is null then continue
      items.push[item]
    return items


  ###*
   * Loop through all the items in the keychain, and pass each one to a
   * function.
   * - fn  {Function} : The function to pass each item to
   * > this
  ###
  eachItem: (fn) ->
    for uuid, item of @items
      fn(item)
    return this


  ###*
   * Generate the profile.js file
   * > string - the profile.js file contents as json
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
    return PROFILE_PREFIX + JSON.stringify(data) + PROFILE_SUFFIX


  ###*
   * This exports all the items currently in the keychain into band files.
   * > object - the band files as { filename: contents }
  ###
  exportBands: ->

    bands = {}

    # Sort items into groups based on the first char of its UUID
    for uuid, item of @items
      id = uuid[0...1]
      bands[id] ?= []
      bands[id].push(item)

    files = {}

    # Generate band files and filenames
    for id, items of bands
      data = {}
      for item in items
        data[item.uuid] = item.toJSON()
      data = BAND_PREFIX + JSON.stringify(data, null, 2) + BAND_SUFFIX
      files["band_#{id}.js"] = data

    return files


module.exports = Keychain
