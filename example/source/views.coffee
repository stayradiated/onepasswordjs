$ = require './dom'

template = (id) ->
  _.template $.id("#{ id }-template").innerHTML

Vent = _.extend Backbone.Events

Views =

  Item: class extends Backbone.View

    tagName: 'li'
    template: template('item')

    events:
      'click': 'select'

    select: =>
      if not @model.detailsUnlocked then @model.unlock('details')
      Vent.trigger 'selectItem', @model

    render: =>
      @$el.html @template( item: @model )
      return this

  Main: class extends Backbone.View

    el: $('.container')

    template: template('item-info')

    events:
      'keydown .locked input': 'keydown'

    initialize: (@keychain) ->

      @input = $('input.unlock')
      @table = $('.items')
      @content = $('.item-info')

      Vent.on 'selectItem', @showItem

      @keychain.event.on 'lock:after', =>
        $.addClass(@el, 'keychain-locked')

      @keychain.event.on 'unlock', =>
        $.removeClass(@el, 'keychain-locked')
        @listItems()

    keydown: (e) =>
      # Only unlock when Enter is pressed
      if e.keyCode is 13 then @unlock()

    unlock: ->
      password = @input.value
      @keychain.unlock(password)
      @input.value = ''

    showItem: (item) =>
      @keychain.rescheduleAutoLock()
      @content.innerHTML = @template(item: item)

    listItems: =>
      @table.innerHTML = ''
      @keychain.eachItem (item) =>
        item.unlock('overview')
        view = new Views.Item(model: item)
        @table.appendChild view.render().el


module.exports = Views
