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

Add `1password` to your `package.json` file.

    {
      "name": "yourapplication",
      "version": "0.1.0",
      "dependencies": {
        "1password": "0.1.0"
      }
    }

Then run the following command

    npm install

OR, if you just want to start playing with the library:

    npm install 1password


## How to Use

__Step 1: Open the keychain__

    Keychain = require('1password');
    keychain = new Keychain();
    keychain.load('./1password.cloudkeychain');

__Step 2: Unlocking the keychain__

    keychain.unlock('password');

__Step 3: Get items__

    keychain.eachItem(function(item) {
      console.log( item.overview.title );
    });

__Step 4: Decrypt item details__

    item = keychain.findItem( 'Facebook' );
    details = keychain.decryptItem( item.uuid );
    console.log( details );


## Main Keychain Methods

### Keychain.create(password, hint)

Returns an empty keychain encrypted using the password specified.

    keychain = Keychain.create( 'password', 'hint' );
    profile = keychain.exportProfile();
    console.log( profile );

This logs the following (indented for readibility):

    var profile={
      "lastUpdatedBy": "Dropbox",
      "updatedAt": 1362617665,
      "profileName": "default",
      "salt": "W0wV8jBiFnRWmqWDl3vaPA==",
      "passwordHint": "hint",
      "masterKey": "b3BkYXRhMDEAAQAAAAAAAGnpNQQJuFTg ..."
      "iterations": 20000,
      "uuid": "A2C1050B56C89557AC2A0FA230F90174",
      "overviewKey": "b3BkYXRhMDFAAAAAAAAAAAbP+65OIhYy ...",
      "createdAt": 1362617665
    };


## Keychain Instance Methods

### Events
#### on(event, id, fn)
#### off(event, id)
#### one(event, id, fn)

### Loading data from files
#### load(filepath)
#### loadProfile(filepath)
#### loadFolders(filepath)
#### loadBands(bands)
#### loadAttachment(attachments)

### Unlocking data
#### unlock(password)
#### lock()
#### rescheduleAutoLock()

### Items
#### createItem(data)
#### addItem(item)
#### getItem(uuid)
#### findItem(query)
#### decryptItem(uuid)
#### eachItem(fn)

### Exporting Data
#### exportProfile()
#### exportBands()

## Compiling

To compile the coffeescript into javascript use grunt:

    grunt --compile

## Tests

Tests are written using [Mocha](http://visionmedia.github.com/mocha/).
To run the tests

    mocha tests

License
-------
This work is licensed under the ISC license.