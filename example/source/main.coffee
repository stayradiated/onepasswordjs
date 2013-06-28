
global.document = document
global.Backbone = Backbone
global._        = _

# Dependencies
$ = require './js/dom'
Keychain = require '../js/keychain'

# OnePasswordJS handles the models and collections for us
# So we are just using BackBone for views
window.App =
  Views: require './js/views'
  state: {}

window.keychain = new Keychain()
window.main = new App.Views.Main(keychain)

keychain.event.on 'unlock', ->
  console.log 'Keychain unlocked'

keychain.event.on 'lock:after', ->
  console.log 'Keychain has been locked'

keychain.load '../data/tests.cloudkeychain', (err) ->
  if err? then log err

# Track input focus - for keyboard shortcuts
App.state.focus = false
for input in $.tag('input')
  input.addEventListener 'focus', -> App.state.focus = true
  input.addEventListener 'blur', -> App.state.focus = false
