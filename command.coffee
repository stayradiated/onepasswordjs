###*
 * @fileOverview A really basic command line interface to demonstrate the
 * CloudKeychain libarary.
 *
 * @example
 * coffee command --open ./data/sample.keychain
 * coffee command --new ./data
 *
###

program = require 'commander'
fs = require 'fs'

Keychain = require './src/keychain'
keychain = null

program
  .version('0.0.1')
  .option('-o, --open <file>', 'Open keychain file')
  .option('-n, --new <file>', 'New keychain file')
  .option('-d, --debug', 'Debug')
  .parse(process.argv)


unlock = (fn) ->
  program.prompt 'Password: ', (password) ->
    if keychain.unlock(password)
      fn()
    else
      console.log 'Incorrect password...\n'
      return unlock(fn)

listItems = ->
  console.log '\n===== ITEMS ====='
  keychain.eachItem (item) ->
    console.log "  - " + item.overview.title
  console.log '=================\n'

displayItem = (item, details) ->
  console.log "Category: ", item.category
  console.log JSON.stringify(item.overview, null, 2)
  if details.sections?
    for section in details.sections
      console.log "\n=== #{section.title} ==="
      for field in section.fields
        console.log "#{field.t}: #{field.v}"
  else if details.fields?
    console.log '\n'
    for field in details.fields
      console.log "#{field.name}: #{field.value}"
  else if details.notesPlain?
    console.log "\nNotes: #{details.notesPlain}"
  else
    console.log JSON.stringify(details, null, 2)
  console.log '\n'

openItem = ->
  program.prompt "Search for item: ", (query) ->
    keychain.rescheduleAutoLock()
    if query is "list"
      listItems()
      return openItem()
    results = keychain.findItem(query)
    if results.length > 0
      item = results[0]
      # console.log JSON.stringify results[0].overview, null, 2
      # uuid = results[0].uuid
      details = item.decryptDetails(keychain.master)
      displayItem(item, details)
    else
      console.log 'Nothing found... Hint: Enter `list` to display all'
    openItem()

createItem = (keychain, fn) ->
  program.prompt
    title: "Item Title: "
    username: "Item Name: "
    password: "Item Password: "
    url: "Item URL: "
    notes: "Item Notes: "
    (data) ->
      item = Keychain.createItem(data, keychain.master, keychain.overview)
      fn keychain.addItem(item).exportBands()


if program.open
  filepath = program.open
  keychain = new Keychain().load(filepath)

  keychain.on 'lock', ->
    console.log '\n Locking the Keychain \n'
    unlock()

  unlock ->
    listItems()
    openItem()

else if program.new
  filepath = program.new
  program.prompt
    password: 'Password: ',
    hint: 'Password Hint: '
    (user) ->
      keychain = Keychain.create(user.password, user.hint)
      fs.mkdirSync "#{filepath}/1Password.cloudkeychain"
      fs.mkdirSync "#{filepath}/1Password.cloudkeychain/default"
      fs.writeFileSync "#{filepath}/1Password.cloudkeychain/default/profile.js", keychain.exportProfile()
      createItem keychain, (bands) ->
        for filename, band of bands
          fs.writeFileSync "#{filepath}/1Password.cloudkeychain/default/#{filename}", band