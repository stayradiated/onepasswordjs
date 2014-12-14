# Password generator

crypto = require('./crypto')

# Constants
LETTERS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
SYMBOLS = '!<>[]{}()=+-_!@#$%^&*.,?/;:\'\"\\'
DIGITS  = '0123456789'
######

# Return a string of `n` length, with characters chosen from `chars`
random = (chars, n) ->
  return '' if n < 0
  len = chars.length
  string = ''
  for i in [0...n] by 1
    index = Math.floor crypto.randomValue() * len
    char = chars[index]
    string += char
  return string

# Merge two strings together randomly
merge = (a, b) ->
  len = a.length + 1
  for i in [0...b.length] by 1
    pos = Math.floor crypto.randomValue() * len
    a = a[0...pos] + b[i] + a[pos..]
    len += 1
  return a

generate =

  # 1Password password generator
  random: (length = 20, digits = 0, symbols = 0) ->
    len = {}
    len.letters = length - digits - symbols
    len.letters = 0 if len.letters < 0
    len.digits = (if digits > length then length else digits)
    len.symbols = length - len.digits - len.letters
    len.symbols = 0 if len.symbols < 0

    password = random(LETTERS, len.letters)

    if len.digits > 0
      digits = random(DIGITS, len.digits)
      password = merge(password, digits)

    if len.symbols > 0
      symbols = random(SYMBOLS, len.symbols)
      password = merge(password, symbols)

    return password

module.exports = generate
