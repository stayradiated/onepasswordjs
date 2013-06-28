# Cloud Keychain for Node.js (v0.2.1)

This is a small library to make it easy to work with
  [1Password's](http://agilebits.com/onepassword) .cloudKeychain files.

This implementation is based on the
  [official Agile Bits documentation](http://learn.agilebits.com/1Password4/Security/keychain-design.html)
  and also the python library [OnePasswordPy](http://github.com/roguelazer/onepasswordpy).

*IMPORTANT NOTE*: I am not in any way affiliated with AgileBits, the makers
  of 1Password. Their software is awesome and you should probably go buy it.

Currently supported:

- Unlock keychain using Master Password
- Load items from band_*.js files
- Unlock item overview, keys and details
- Create keychains and items

Todo:

- Find out how to calcuate the HMAC of items correctly
- Actually do something with item data (instead of just handing back the raw
JSON)
- Get syncing working.
- Add memoize pattern to opdata class to speed up item locking when no data has changed.

## Installation

    npm install 1password


## How to Use

__Step 1: Open the keychain__

    Keychain = require( '1password' );
    keychain = new Keychain();
    keychain.load( './1password.cloudkeychain', function( err ) {
        console.log( 'Keychain has loaded' ); 
    });

__Step 2: Unlocking the keychain__

    keychain.unlock( 'password' );

    if ( keychain.unlocked ) {
        console.log( 'Successfully unlocked keychain' );
    } else {
        console.log( 'Error: Could not unlock keychain' );
    }

__Step 3: Get items__

    keychain.eachItem( function( item ) {
      console.log( item );
    });

__Step 4: Decrypt item details__

    item = keychain.findItems( 'Facebook' )[0];
    item.unlockDetails();
    console.log( item.details );


# Main Keychain Methods

## Keychain.create(password, settings)

Returns an empty keychain encrypted using the password specified.

    keychain = Keychain.create( 'password', {
        passwordHint: 'hint'
    });
    profile = keychain.exportProfile();
    console.log( profile );

The `settings` parameter is an object and can overwrite any of the default
values. However extra settings cannot be added. The default settings are:
    
    settings = {
      uuid: Crypto.generateUuid(),
      salt: Crypto.randomBytes(16),
      createdAt: currentTime,
      updatedAt: currentTime,
      iterations: 10000,
      profileName: 'default',
      passwordHint: '',
      lastUpdatedBy: 'Dropbox'
    };

This logs the following (indented and trimmed for readibility):

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


# Keychain Instance Methods

## Events

Events are implemented using the NodeJS EventEmitter. The API is available on
the [NodeJS.org website](http://nodejs.org/api/events.html).

To use the EventEmitter:

    keychain = new Keychain();
    keychain.event.on('event', function(args) {
        console.log('Event fired!', args);
    });
    keychain.event.emit('event', 'random data');


### Event: 'unlock'

    function() { }

When the keychain is unlocked.


### Event: 'lock:before'

    function (autolock) { }

When the keychain is locked. If the keychain was locked automatically by a
timer, then `autolock` will be true. Used to run code before the keychain is
locked.

### Event: 'lock:after'
    
    function (autolock) { }

When the keychain is locked. If the keychain was locked automatically by the
timer, then `autolock` will be true. Used to run code after the keychain has
been locked.


## Loading data from files

Load keychain data from a file on disk.

### load(filepath, callback)

This is the main loading function and probably the only one you'll only ever need to use.
`filepath` points to a `.cloudkeychain` folder and it will go through and load all files it finds using the other functions.

    keychain.load( './1password.cloudkeychain', function(err) {
        if ( err ) return console.log( err.message );
        console.log( 'Successfully loaded keychain' );
    });

### loadProfile(filepath, rawData)

Loads the `profile.js` file data into the keychain.
If you already have profile.js then set `rawData` to `true`.

    filename = './1password.cloudkeychain/default/profile.js';
    keychain.loadProfile( filename );

    // Alternative
    profileData = readFileContents( filename )
    keychain.loadProfile( profileData, true )

### loadFolders(filepath)

__Warning: Not yet implemented.__

Load the `folders.js` file data into the keychain.

    keychain.loadFolders( './1password.cloudkeychain/default/folders.js' );

### loadBands(bands)

`bands` is an array of filepaths pointing to each band file.

    keychain.loadBands([
      './1password.cloudkeychain/default/band_0.js',
      './1password.cloudkeychain/default/band_1.js',
      './1password.cloudkeychain/default/band_2.js'
    ]);

### loadAttachment(attachments)

__Warning: Not yet implemented__

`attachments` is an array of filepaths pointing to each band file.

    keychain.loadAttachments([
      './1password.cloudkeychain/default/026AA7B7333B4F925F16DE9E21B912B7_5754B83288A34CD39DE64B45C2F05A9D.attachment',
      './1password.cloudkeychain/default/6F8CDF100CC99FD55053B77492D97487_072A1462CBDE4E2488FB2DA16D96B84B.attachment'
    ]);


## Unlocking data

Handle the keychain unlocked status.

### unlock(password)

Unlock the keychain's master and overview keys using `password`.
It will automatically lock itself after 60 seconds, unless `rescheduleAutoLock` is called.

    status = keychain.unlock( 'password' );
    console.log( 'Keychain was unlocked successfully: ' + status );

### lock()

Lock the keychain.
This will dump the contents of all decrypted data, returning the state back to when the keychain was originally locked.

    keychain.lock();

### rescheduleAutoLock()

This will reschedule the autolock time.
It should only be called when the user does something importantt in the app.

    keychain.rescheduleAutoLock()


### changePassword(currentPassword, newPassword)

__Warning: Not yet tested__

This function will regenerate the master and overview keys using `newPassword`.
The `currentPassword` is required, as it is not stored in memory for security
reasons.

    keychain.changePassword( 'fred', 'phil' );


## Items

Working with items.

### createItem(data)

Creates a new instance of an item using the information in `data`.
It returns the item instance, but it does not add it to the keychain. Use `addItem()` to do that.

    item = keychain.createItem({
      title: 'Github',
      username: 'wendyappleseed',
      password: 'password',
      url: 'github.com',
      notes: ''
    });

### addItem(item)

Adds an item to the keychain.
If `item` is not an instance of an item, it is turned into one using `new Item(item)`.

    keychain.addItem(item);

### getItem(uuid)

Get an item by its UUID.

    item = keychain.getItem('B1198E4C643E73A6226B89BB600371A9');

### findItems(query)

Search the keychain for an item by its name or location.
Returns an array of items.

    items = keychain.findItems('github');

### eachItem(fn)

Loop through all the items in the keychain.
Calls fn with the arguments `[item]`.

    keychain.eachItem(function(item) {
      console.log( item );
    });


## Exporting Data

Export keychain data into stringified JSON. Ready for writing to disk.

### exportProfile()

Export the profile.js file.

    profile = keychain.exportProfile();
    writeFile('profile.js', profile);

### exportBands()

Export the band files (which holds the item data).
Returns an object.

    bands = keychain.exportBands()

    console.log( bands );

    {
      "band_0.js": "ld({\n  \"B1198E4C643E73A6226B89BB600371A9\": {\n    \"category\": \"001\" ...",
      filename: filedata
    }


# Item Instance Methods

### load(data)
This is used to load the raw JSON data in a band file into an item.
Fields such as `hmac`, `k`, `o` and `d` are converted from base64.

	item.load({
		category: '106',
		created: 1361850113,
		d: 'b3BkYXRhMDHlAgAAAAAAANQpT0oUzF1E ...',
		hmac: '/Qzi7Gy37hIV18NgXffDMmt3iPZKVxIFlvvULxf5iCQ=',
		k: '3OoNrhpqKeBkeVAHTgwXPjlEL++QJAhx ...',
		o: 'b3BkYXRhMDElAAAAAAAAAEfvS1hvP9Ue …',
		tx: 1361857114,
		updated: 1361857114,
		uuid: 'F11FC7E27E3645D09D2670F04EF5F252'
	});

### lock(type)
Lock the item by deleting secure information such as the item keys, overview data and details.

    console.log( item.overview ); // {...} Overview data
    item.lock('overview');
    console.log( item.overview ); // undefined


### unlock(type)
Unlock the item by decrypting secure information such as the item keys, overview data and details.

    details = item.unlock('details')

### encrypt(type)
Encrypt item details.

    item.unlock('details');
    item.details.data = true;
    item.encrypt('details');
    item.lock('details');

### toJSON()
Export an item into a JSON object that can be saved in a band file.

    json = item.toJSON();

### match(query)
Check if an item matches a query. Useful for searching through a keychain. It checks the title and URL of the item and is case insensitive.

    item.overview.title == 'Facebook';
    item.match('facebook'); // true
    item.match('book');     // true
    item.match('skype');    // false



## Compiling

To compile the coffeescript into javascript use `cake`:

    cake build

## Tests

Tests are written in JavaScript using [Mocha](http://visionmedia.github.com/mocha/).
To run the tests

    sudo npm install -g mocha
    mocha tests

Or if you don't want to install mocha globally:

    npm install .
    cake tests

License
-------
This work is licensed under the ISC license.
