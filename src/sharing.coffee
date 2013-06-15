Keychain = require('./keychain')
Password = require('./password')
Item     = require('./item')

# Constants
TYPE_SHARED_KEYCHAIN = 'Webkeys Shared Keychain'

# data = {
#   title: 'Shared Keychain'
#   username: '<keychain name>'
#   password: '<keychain password'>
#   url: '<keychain path>'
#   notes: 'Webkeys Shared Keychain'
# }
# item = keychain.createItem(data)
# keychain.addItem(item)

create = ->
  password = Password.random(30, 5, 5)
  keychain = Keychain.create(password)

save = (keychain, password) ->
  item = new Item({
    title: 'Shared Keychain'
    username: 'New Shared Keychain'
    password: password
    url: keychain.keychainPath
  })

# Wrap findItems to search all keychains
findItems = Keychain::findItems

Keychain::findItems = (query, level=1) ->
  # Only search main keychain
  if level is 0 then return findItems(query)
  # Else search all keychains
  results = for id, keychain of @shared.all
    findItems(query)
  # Clever way to concatenate an array of arrays
  return Array::concat.apply(results[0] or [], results[1..])


# Manage shared keychains
Keychain::shared =

  all: {},

  index: 0,

  # Detect if an item stores a Shared Keychain
  detect: (item) ->
    if item.type is TYPE_SHARED_KEYCHAIN
      item.hidden = true
      console.log item
      # @shared.load(keychain)

  load: (keychain) ->
    id = @index++
    @all[id] = keychain
    return id

  unload: (id) ->
    delete @all[id]

  list: ->
    for id, keychain of @all
      id: id,
      path: keychain.keychainPath

  get: (id) ->
    return @all[id]

module.exports = Keychain
