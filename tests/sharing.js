var assert = require('assert');
var Keychain = require('../js/sharing');

describe('Shared Keychain', function() {

  it('should load multiple keychains', function() {

    main = new Keychain();
    main.load('./data/tests.cloudkeychain', function() {

      shared = new Keychain();
      shared.load('./data/1Password.cloudkeychain', function() {

        main.shared.load(shared);
        list = main.shared.list();

        assert.equal(list[0].id, '0');
        assert.equal(list[0].path, './data/1Password.cloudkeychain');
        assert.equal(main.shared.get(0) instanceof Keychain, true);

      });

    });

  });

});
