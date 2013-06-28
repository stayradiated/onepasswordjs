var assert = require('assert');
var password = require('../js/password.js');

describe('Password Generator', function() {

  it('should generate a random password', function() {

    pass = password.random(30, 10, 10);
    assert.equal( pass.length, 30 );

  });

});
