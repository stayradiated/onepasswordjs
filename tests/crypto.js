var assert = require('assert');
var Crypto = require('../js/crypto');

describe('Crypto', function() {

  /**
   * ENCRYPTION and DECRYPTION
  */
  (function() {

    var encoding = 'hex';
    var plaintext = new Buffer('0123456789ABCDEF');
    var key = "f0fb2c2dea3b28bd08a60c7049a5f62c3388872b82160a005ad3eb00ff0f69f3";
    var iv = "6993260ef345b11c7c53e4dac76326f9";
    var ciphertext = '489aa87997c0b113e5000111c32a79cd';

    it('should encrypt using AES', function() {
      var encrypted = Crypto.encrypt(plaintext, key, iv, encoding);
      assert.equal(encrypted, ciphertext);
    });

    it('should decrypt using AES', function() {
      var decrypted = Crypto.decrypt(ciphertext, key, iv);
      assert.equal(decrypted.toString(), plaintext.toString());
    });

  }());


  /**
   * PBKDF2
  */
  it('should do PBKDF2 correctly', function() {
    var password = 'password';
    var salt = '0123456789ABCDEF';
    var pbkdf2 = Crypto.pbkdf2(password, salt, 10000, 512).toString('hex');
    assert.equal(pbkdf2, 'f119d9566f66c185d1616fc88d7edcb003abd7bcef4e1dcf3fbc628cb9acface5fdda2f14320661feddf6ebda3e10f313ba7c2a12e532050668d229d67f9f6a0');
  });


  /**
   * HMAC
  */
  it('should generate the correct HMAC', function() {
    var hmac = Crypto.hmac('bdd50cd25aacbab410ce7b8b9dcb97b17340be26793632fc80983d3bf525e0d7', '1bb1cc1d4f43b0a632ffe2ab1520f44df989ad33b2d82635d600aae8e05f5b4e', 256, 'hex');
    assert.equal(hmac, '83f6ba83b23b2efa853a9d695fb5e349d4ea65360478fec345ee14b70c5f4699');
  });


  /**
   * HASH
  */
  it('should hash', function() {
    var hash = Crypto.hash('f04a1b185b1bfb92c73ecd430642b59332190b94e7ea0b5a9c65490032dcf253', 256, 'hex');
    assert.equal(hash, 'bf1b0a9672b18dd90790fbe044155b1750e978fa832237ff4fb615c5e235034f');
  });


  /**
   * Padding
  */
  (function() {

    var input = new Buffer('Yellow Submarine');
    var output;

    it('should pad', function() {
      output = Crypto.pad(input);
      // Should be a multiple of 16
      assert.equal( output.length % 16, 0 );
    });

    it('should unpad', function() {
      var unpadded = Crypto.unpad(input.length, output);
      // Should match the input
      assert.equal( unpadded.toString(), input.toString() )
    });

  }());


  /**
   * Random Data
  */
  it('should generate random data', function() {
    var bytes = Crypto.randomBytes(64);
    assert.equal(bytes.length, 64);
  });


  /**
   * Encoding
  */
  it('should convert data to a Buffer', function() {
    var data = Crypto.randomBytes(64);
    var hex = data.toString('hex');
    var buffer = Crypto.toBuffer(hex, 'hex');
    assert.equal(buffer instanceof Buffer, true);
  });

  it('should convert data to Hex', function() {
    var data = Crypto.randomBytes(64);
    var hex = Crypto.toHex(data);
    assert.equal(data.toString('hex'), hex);
  });

  it('should convert data from Base64', function() {
    var data = Crypto.randomBytes(64);
    var buffer = Crypto.fromBase64(data.toString('base64'));
    assert.equal(buffer.toString('hex'), data.toString('hex'));
  });

  it('should concat buffers', function() {
    var a = Crypto.randomBytes(16);
    var b = Crypto.randomBytes(16);
    var c = Crypto.randomBytes(16);
    var d = Crypto.concat([a, b, c]);
    assert.equal(d.length, 48);
    assert.equal(d.slice(0, 16).toString(), a.toString());
    assert.equal(d.slice(16, 32).toString(), b.toString());
    assert.equal(d.slice(32, 48).toString(), c.toString());
  });

  it('should read and write little endian numbers', function() {
    var numbers = {
      8192: "0020000000000000",
      256: "0001000000000000",
      64: "4000000000000000"
    };

    var val, endian;
    for (val in numbers) {
      endian = numbers[val];
      assert.equal(Crypto.parseLittleEndian(endian), val);
      assert.equal(Crypto.littleEndian(val), endian);
    }
  });

  it('should convert decimal to hex', function() {
    var numbers = {
      0: "00",
      60: "3c",
      128: "80",
      160: "a0",
      255: "ff"
    };

    var dec, hex;
    for (dec in numbers) {
      hex = numbers[dec];
      dec = parseInt(dec, 10);
      assert.equal(Crypto.dec2hex(dec), hex);
    }
  });

  it('should convert binary to hex', function() {
    var hex = 'bada55c0ffee';
    var binary = 'ºÚUÀÿî';
    assert.equal(Crypto.bin2hex(binary), hex);
  });

  it('should generate UUIDS', function() {
    var uuid = Crypto.generateUuid();
    assert.equal(uuid.length, 32);
  });

});
