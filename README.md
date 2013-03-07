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

    item = keychain.findItems( 'Facebook' );
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

Used to listen for events in the keychain. Their is currently only one event that is triggered at the moment

  - 'lock'

#### on(event, [id], fn)

Listens for the event `event` and when triggered fires `fn`.
If no `id` is specified, an id is generated automatically.
Returns the `id`.

    keychain.on('lock', function(autolock) {
      console.log( 'The keychain has been locked' );
    });

#### off(event, [id])

If an `id` is specified, it will remove that event listener.
If no `id` is specifed, then it will remove all event listeners for that `event`.

    keychain.off( 'lock' );

#### one(event, [id], fn)

The same as `on` but will only run once.


### Loading data from files

Load keychain data from a file on disk.

#### load(filepath)

This is the main loading function and probably the only one you'll only ever need to use.
`filepath` points to a `.cloudkeychain` folder and it will go through and load all files it finds using the other functions.

    keychain.load( './1password.cloudkeychain' );

#### loadProfile(filepath)

Loads the `profile.js` file data into the keychain.

    keychain.loadProfile( './1password.cloudkeychain/default/profile.js' );

#### loadFolders(filepath)

Load the `folders.js` file data into the keychain.

    keychain.loadFolders( './1password.cloudkeychain/default/folders.js' );

#### loadBands(bands)

`bands` is an array of filepaths pointing to each band file.

    keychain.loadBands([
      './1password.cloudkeychain/default/band_0.js',
      './1password.cloudkeychain/default/band_1.js',
      './1password.cloudkeychain/default/band_2.js'
    ]);

#### loadAttachment(attachments)

`attachments` is an array of filepaths pointing to each band file.

    keychain.loadAttachments([
      './1password.cloudkeychain/default/026AA7B7333B4F925F16DE9E21B912B7_5754B83288A34CD39DE64B45C2F05A9D.attachment',
      './1password.cloudkeychain/default/6F8CDF100CC99FD55053B77492D97487_072A1462CBDE4E2488FB2DA16D96B84B.attachment'
    ]);


### Unlocking data

Handle the keychain unlocked status.

#### unlock(password)

Unlock the keychain's master and overview keys using `password`.
It will automatically lock itself after 60 seconds, unless `rescheduleAutoLock` is called.

    status = keychain.unlock( 'password' );
    console.log( 'Keychain was unlocked successfully: ' + status );

#### lock()

Lock the keychain.
This will dump the contents of all decrypted data, returning the state back to when the keychain was originally locked.

    keychain.lock();

#### rescheduleAutoLock()

This will reschedule the autolock time.
It should only be called when the user does something important in the app.

    keychain.rescheduleAutoLock()


### Items

Working with items.

#### createItem(data)

Creates a new instance of an item using the information in `data`.
It returns the item instance, but it does not add it to the keychain. Use `addItem()` to do that.

    item = keychain.createItem({
      title: 'Github',
      username: 'wendyappleseed',
      password: 'password',
      url: 'github.com',
      notes: ''
    });

#### addItem(item)

Adds an item to the keychain.
If `item` is not an instance of an item, it is turned into one using `new Item(item)`.

    keychain.addItem(item);

#### getItem(uuid)

Get an item by its UUID.

    item = keychain.getItem('B1198E4C643E73A6226B89BB600371A9');

#### findItems(query)

Search the keychain for an item by its name or location.
Returns an array of items.

    items = keychain.findItems('github');

#### decryptItem(item|uuid)

Decrypt an items details. Can be passed an item or an item UUID.

    details = keychain.decryptItem(item);
    details = keychain.decryptItem('B1198E4C643E73A6226B89BB600371A9');

#### eachItem(fn)

Loop through all the items in the keychain.
Calls fn with the arguments `[item]`.

    keychain.eachItem(function(item) {
      console.log( item );
    });


### Exporting Data

Export keychain data into stringified JSON. Ready for writing to disk.

#### exportProfile()

Export the profile.js file.

    profile = keychain.exportProfile();
    writeFile('profile.js', profile);

#### exportBands()

Export the band files (which holds the item data).
Returns an object.

    bands = keychain.exportBands()

    console.log( bands );

    {
      "band_0.js": "ld({\n  \"B1198E4C643E73A6226B89BB600371A9\": {\n    \"category\": \"001\" ...",
      filename: filedata
    }

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