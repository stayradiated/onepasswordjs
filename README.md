# Cloud Keychain for Node.js (v0.1)

This is a small library to make it easy to work with
  [1Password's](http://agilebits.com/onepassword) .cloudKeychain files.

This implementation is based on the
  [official Agile Bits documentation](http://learn.agilebits.com/1Password4/Security/keychain-design.html)
  and also the python library [OnePasswordPy](http://github.com/roguelazer/onepasswordpy).

*IMPORTANT NOTE*: I am not in any way affiliated with AgileBits, the makers
  of 1Password. Their software is awesome and you should probably go buy it.
  Please don't sue me!

Currently supported:

- Unlock keychain using Master Password
- Load items from band_*.js files
- Unlock item overview, keys and details
- Create keychains and items


Todo:

- Find out how to calcuate the HMAC of items correctly
- Actually do something with item data (instead of just handing back the raw
JSON)

## Installation

Install via NPM:

    npm install 1password

Then require it:

    Keychain = require('1passwordjs')
    keychain = new Keychain()
    keychain.open('./1password.cloudkeychain')
    keychain.unlock('password')


## Tests

Tests are written using [Mocha](http://visionmedia.github.com/mocha/).
To run the tests

    mocha --compilers coffee:coffee-script tests

License
-------
This work is licensed under the ISC license.