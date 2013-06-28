class $

  constructor: (query) ->
    return document.querySelector(query)

  @find: (parent, query) ->
    parent.querySelector(query)

  @findAll: (parent, query) ->
    parent.querySelectorAll(query)

  @create: (tag) ->
    document.createElement(tag)

  @append: (el, parent=document.body) ->
    parent.appendChild(el)

  @prepend: (el) ->
    document.body.insertBefore(el, document.body.firstChild)

  @tag: (tag) ->
    document.getElementsByTagName(tag)

  @id: (id) ->
    document.getElementById(id)

  @class: (className) ->
    document.getElementsByClassName(className)

  @all: (query) ->
    document.querySelectorAll(query)

  @addClass: (el, className...) ->
    el.classList.add(className...)

  @removeClass: (el, className) ->
    el.classList.remove(className)

  @toggleClass: (el, className, value) ->
    el.classList.toggle(className, value)

  @hasClass: (el, className) ->
    el.classList.contains(className)

  @css: (el, prop, val) ->
    el.style[prop] = val

module.exports = $
