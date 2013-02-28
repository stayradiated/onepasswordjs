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

Keychain = require './keychain/keychain'

program
  .version('0.0.1')
  .option('-o, --open <file>', 'Open keychain file')
  .option('-n, --new <file>', 'New keychain file')
  .option('-d, --debug', 'Debug')
  .parse(process.argv)

unlock = (fn) ->
  program.prompt 'Password: ', (password) ->
    if keychain.unlock(password)
      console.log 'Keychain unlocked...'
      fn()
    else
      console.log 'Incorrect password...\n'
      return unlock(fn)

openItem = ->
  program.prompt "Name: ", (query) ->
    results = keychain.findItem(query)
    if results.length > 0
      item = results[0]
      # console.log JSON.stringify results[0].overview, null, 2
      # uuid = results[0].uuid
      console.log JSON.stringify item.decryptDetails(keychain.master), null, 2
    else
      console.log 'Nothing found...'
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

  unlock ->
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