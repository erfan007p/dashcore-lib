/* eslint-disable */
// TODO: Remove previous line and work through linting issues at next edit

'use strict';

var should = require('chai').should();
var expect = require('chai').expect;

var bitcore = require('../index.js');
var Point = bitcore.crypto.Point;
var BN = bitcore.crypto.BN;
var PublicKey = bitcore.PublicKey;
var PrivateKey = bitcore.PrivateKey;
var Address = bitcore.Address;
var Networks = bitcore.Networks;

/* jshint maxlen: 200 */

describe('PublicKey', function () {
  /* jshint maxstatements: 30 */

  var invalidPoint =
    '0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';

  describe('validating errors on creation', function () {
    it('errors if data is missing', function () {
      (function () {
        return new PublicKey();
      }.should.throw(
        'First argument is required, please include public key data.'
      ));
    });

    it('errors if an invalid point is provided', function () {
      (function () {
        return new PublicKey(invalidPoint);
      }.should.throw('Point does not lie on the curve'));
    });

    it('errors if a point not on the secp256k1 curve is provided', function () {
      (function () {
        return new PublicKey(new Point(1000, 1000));
      }.should.throw('Point does not lie on the curve'));
    });

    it('errors if the argument is of an unrecognized type', function () {
      (function () {
        return new PublicKey(new Error());
      }.should.throw('First argument is an unrecognized data format.'));
    });
  });

  describe('instantiation', function () {
    it('from a private key', function () {
      var privhex =
        '906977a061af29276e40bf377042ffbde414e496ae2260bbf1fa9d085637bfff';
      var pubhex =
        '02a1633cafcc01ebfb6d78e39f687a1f0995c62fc95f51ead10a02ee0be551b5dc';
      var privkey = new PrivateKey(new BN(Buffer.from(privhex, 'hex')));
      var pk = new PublicKey(privkey);
      pk.toString().should.equal(pubhex);
    });

    it('problematic secp256k1 public keys', function () {
      var knownKeys = [
        {
          wif: 'cZ3n7ZxPY4fyd55wWX8hKvYZYEVeysStHLnz69M5HJBTvchKvymW',
          priv: '56240af369921402d83a44700245ee12fa04b7bae2d6b4cd8b2f276859e51e6a',
          pub: '039611f38f43d91c8b7af296d99a15bbde28eed632f8b36d72df599e9d8f774d5e',
          pubx: '9611f38f43d91c8b7af296d99a15bbde28eed632f8b36d72df599e9d8f774d5e',
          puby: '20b01662da186ac19e1a5abbfdc444963a56deb1ba325a190de856fb3ed45b5b',
        },
        {
          wif: 'cYqncuJLhvxYrEhNHn2oynniKknkf5jdB1gx1zHKK28RcvvqtPUC',
          priv: '4ff8d6873852ba5dc0836d815ca1c49b30e27204579d1fdd710436a8a8338915',
          pub: '02d9bc4f4f126e968fa062b40c2bf7e0bea741138a7b327d2140d2c7f76248344b',
          pubx: 'd9bc4f4f126e968fa062b40c2bf7e0bea741138a7b327d2140d2c7f76248344b',
          puby: 'f906518496e753b5660077d83cb3ef36ab0483eef66d289b06edd013bd4d63dc',
        },
      ];

      for (var i = 0; i < knownKeys.length; i++) {
        var privkey = new PrivateKey(knownKeys[i].wif);
        var pubkey = privkey.toPublicKey();
        pubkey.toString().should.equal(knownKeys[i].pub);
        pubkey.point.x.toString('hex').should.equal(knownKeys[i].pubx);
        pubkey.point.y.toString('hex').should.equal(knownKeys[i].puby);
      }
    });

    it('from a compressed public key', function () {
      var publicKeyHex =
        '031ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a';
      var publicKey = new PublicKey(publicKeyHex);
      publicKey.toString().should.equal(publicKeyHex);
    });

    it('from another publicKey', function () {
      var publicKeyHex =
        '031ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a';
      var publicKey = new PublicKey(publicKeyHex);
      var publicKey2 = new PublicKey(publicKey);
      publicKey.should.equal(publicKey2);
    });

    it('sets the network to defaultNetwork if none provided', function () {
      var publicKeyHex =
        '031ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a';
      var publicKey = new PublicKey(publicKeyHex);
      publicKey.network.should.equal(Networks.defaultNetwork);
    });

    it('from a hex encoded DER string', function () {
      var pk = new PublicKey(
        '041ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341'
      );
      should.exist(pk.point);
      pk.point
        .getX()
        .toString(16)
        .should.equal(
          '1ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a'
        );
    });

    it('from a hex encoded DER buffer', function () {
      var pk = new PublicKey(
        Buffer.from(
          '041ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341',
          'hex'
        )
      );
      should.exist(pk.point);
      pk.point
        .getX()
        .toString(16)
        .should.equal(
          '1ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a'
        );
    });

    it('from a point', function () {
      var p = new Point(
        '86a80a5a2bfc48dddde2b0bd88bd56b0b6ddc4e6811445b175b90268924d7d48',
        '3b402dfc89712cfe50963e670a0598e6b152b3cd94735001cdac6794975d3afd'
      );
      var a = new PublicKey(p);
      should.exist(a.point);
      a.point.toString().should.equal(p.toString());
      var c = new PublicKey(p);
      should.exist(c.point);
      c.point.toString().should.equal(p.toString());
    });
  });

  describe('#id', function () {
    it('should return Public Key hash', function () {
      var pk = new PublicKey(
        '041ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341'
      );

      pk.hash.should.deep.equal(pk._getID());
    });
  });

  describe('#hash', function () {
    it('should return Public Key hash', function () {
      var pk = new PublicKey(
        '041ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341'
      );

      pk.hash.should.deep.equal(pk._getID());
    });
  });

  describe('#getValidationError', function () {
    it('should recieve an invalid point error', function () {
      var error = PublicKey.getValidationError(invalidPoint);
      should.exist(error);
      error.message.should.equal('Point does not lie on the curve');
    });

    it('should recieve a boolean as false', function () {
      var valid = PublicKey.isValid(invalidPoint);
      valid.should.equal(false);
    });

    it('should recieve a boolean as true for uncompressed', function () {
      var valid = PublicKey.isValid(
        '041ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341'
      );
      valid.should.equal(true);
    });

    it('should recieve a boolean as true for compressed', function () {
      var valid = PublicKey.isValid(
        '031ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a'
      );
      valid.should.equal(true);
    });
  });

  describe('#fromPoint', function () {
    it('should instantiate from a point', function () {
      var p = new Point(
        '86a80a5a2bfc48dddde2b0bd88bd56b0b6ddc4e6811445b175b90268924d7d48',
        '3b402dfc89712cfe50963e670a0598e6b152b3cd94735001cdac6794975d3afd'
      );
      var b = PublicKey.fromPoint(p);
      should.exist(b.point);
      b.point.toString().should.equal(p.toString());
    });

    it('should error because paramater is not a point', function () {
      (function () {
        PublicKey.fromPoint(new Error());
      }.should.throw('First argument must be an instance of Point.'));
    });
  });

  describe('#json/object', function () {
    it('should input/ouput json', function () {
      var json = JSON.stringify({
        x: '1ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a',
        y: '7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341',
        compressed: false,
      });
      var pubkey = new PublicKey(JSON.parse(json));
      JSON.stringify(pubkey).should.deep.equal(json);
    });

    it('fails if "y" is not provided', function () {
      expect(function () {
        return new PublicKey({
          x: '1ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a',
        });
      }).to.throw();
    });

    it('fails if invalid JSON is provided', function () {
      expect(function () {
        return PublicKey._transformJSON('¹');
      }).to.throw();
    });

    it('works for X starting with 0x00', function () {
      var a = new PublicKey(
        '030589ee559348bd6a7325994f9c8eff12bd5d73cc683142bd0dd1a17abc99b0dc'
      );
      var b = new PublicKey('03' + a.toObject().x);
      b.toString().should.equal(a.toString());
    });
  });

  describe('#fromPrivateKey', function () {
    it('should make a public key from a privkey', function () {
      should.exist(PublicKey.fromPrivateKey(PrivateKey.fromRandom()));
    });

    it('should error because not an instance of privkey', function () {
      (function () {
        PublicKey.fromPrivateKey(new Error());
      }.should.throw('Must be an instance of PrivateKey'));
    });
  });

  describe('#fromBuffer', function () {
    it('should parse this uncompressed public key', function () {
      var pk = PublicKey.fromBuffer(
        Buffer.from(
          '041ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341',
          'hex'
        )
      );
      pk.point
        .getX()
        .toString(16)
        .should.equal(
          '1ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a'
        );
      pk.point
        .getY()
        .toString(16)
        .should.equal(
          '7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341'
        );
    });

    it('should parse this compressed public key', function () {
      var pk = PublicKey.fromBuffer(
        Buffer.from(
          '031ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a',
          'hex'
        )
      );
      pk.point
        .getX()
        .toString(16)
        .should.equal(
          '1ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a'
        );
      pk.point
        .getY()
        .toString(16)
        .should.equal(
          '7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341'
        );
    });

    it('should throw an error on this invalid public key', function () {
      (function () {
        PublicKey.fromBuffer(
          Buffer.from(
            '091ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a',
            'hex'
          )
        );
      }.should.throw());
    });

    it('should throw error because not a buffer', function () {
      (function () {
        PublicKey.fromBuffer(
          '091ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a'
        );
      }.should.throw('Must be a hex buffer of DER encoded public key'));
    });

    it('should throw error because buffer is the incorrect length', function () {
      (function () {
        PublicKey.fromBuffer(
          Buffer.from(
            '041ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a34112',
            'hex'
          )
        );
      }.should.throw('Length of x and y must be 32 bytes'));
    });
  });

  describe('#fromDER', function () {
    it('should parse this uncompressed public key', function () {
      var pk = PublicKey.fromDER(
        Buffer.from(
          '041ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341',
          'hex'
        )
      );
      pk.point
        .getX()
        .toString(16)
        .should.equal(
          '1ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a'
        );
      pk.point
        .getY()
        .toString(16)
        .should.equal(
          '7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341'
        );
    });

    it('should parse this compressed public key', function () {
      var pk = PublicKey.fromDER(
        Buffer.from(
          '031ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a',
          'hex'
        )
      );
      pk.point
        .getX()
        .toString(16)
        .should.equal(
          '1ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a'
        );
      pk.point
        .getY()
        .toString(16)
        .should.equal(
          '7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341'
        );
    });

    it('should throw an error on this invalid public key', function () {
      (function () {
        PublicKey.fromDER(
          Buffer.from(
            '091ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a',
            'hex'
          )
        );
      }.should.throw());
    });
  });

  describe('#fromString', function () {
    it('should parse this known valid public key', function () {
      var pk = PublicKey.fromString(
        '041ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341'
      );
      pk.point
        .getX()
        .toString(16)
        .should.equal(
          '1ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a'
        );
      pk.point
        .getY()
        .toString(16)
        .should.equal(
          '7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341'
        );
    });
  });

  describe('#fromX', function () {
    it('should create this known public key', function () {
      var x = BN.fromBuffer(
        Buffer.from(
          '1ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a',
          'hex'
        )
      );
      var pk = PublicKey.fromX(true, x);
      pk.point
        .getX()
        .toString(16)
        .should.equal(
          '1ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a'
        );
      pk.point
        .getY()
        .toString(16)
        .should.equal(
          '7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341'
        );
    });

    it('should error because odd was not included as a param', function () {
      var x = BN.fromBuffer(
        Buffer.from(
          '1ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a',
          'hex'
        )
      );
      (function () {
        return PublicKey.fromX(null, x);
      }.should.throw('Must specify whether y is odd or not (true or false)'));
    });
  });

  describe('#toBuffer', function () {
    it('should return this compressed DER format', function () {
      var x = BN.fromBuffer(
        Buffer.from(
          '1ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a',
          'hex'
        )
      );
      var pk = PublicKey.fromX(true, x);
      pk.toBuffer()
        .toString('hex')
        .should.equal(
          '031ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a'
        );
    });

    it('should return this uncompressed DER format', function () {
      var x = BN.fromBuffer(
        Buffer.from(
          '1ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a',
          'hex'
        )
      );
      var pk = PublicKey.fromX(true, x);
      pk.toBuffer()
        .toString('hex')
        .should.equal(
          '031ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a'
        );
    });
  });

  describe('#toDER', function () {
    it('should return this compressed DER format', function () {
      var x = BN.fromBuffer(
        Buffer.from(
          '1ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a',
          'hex'
        )
      );
      var pk = PublicKey.fromX(true, x);
      pk.toDER()
        .toString('hex')
        .should.equal(
          '031ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a'
        );
    });

    it('should return this uncompressed DER format', function () {
      var pk = PublicKey.fromString(
        '041ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341'
      );
      pk.toDER()
        .toString('hex')
        .should.equal(
          '041ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341'
        );
    });
  });

  describe('#toAddress', function () {
    it('should output this known mainnet address correctly', function () {
      var pk = new PublicKey(
        '03c87bd0e162f26969da8509cafcb7b8c8d202af30b928c582e263dd13ee9a9781'
      );
      var address = pk.toAddress('livenet');
      address.toString().should.equal('GSwqJ9DTmLSJWhhdHnj1Jz2uz7QSP8eXWh');
    });

    it('should output this known testnet address correctly', function () {
      var pk = new PublicKey(
        '0293126ccc927c111b88a0fe09baa0eca719e2a3e087e8a5d1059163f5c566feef'
      );
      var address = pk.toAddress('testnet');
      address.toString().should.equal('nHrjmVrrLUbVrqWRSiM7naz2LXMPRvEzoD');
    });
  });

  describe('hashes', function () {
    // wif private key, address
    // see: https://github.com/dashpay/dash/blob/master/src/test/key_tests.cpp#L20
    var data = [
      [
        'WKQCxDCKqaVdo1kCWPQL3kK1Ye4yhSU6NxZ3yHnRgNVwHQ3XsbX5',
        'GYQB3b2EhTHQcPT4SmnFmE8Jmc1a7uTNg1',
      ],
      [
        'WQQxP5YVhxX76kU3cAQyYifibAN8QMp2vqGccUnfLrXLmzcyE9MW',
        'GRDScwm14buqH1Wv1K6SMwNKGUHa4Jt2nb',
      ],
      [
        'WKZFCAsCvsFbcyYrKqyvCyD5xNRGirtfS46xcekwvxA77RtdDf5X',
        'GYZRiAQRyXnwzgmvv5ma6cisByNhaRc8AU',
      ],
      [
        'WLi68KLDqpRLKyYLfsAq2e7gR1BfUZpLsfgbZ1ZG3ywdd52veKFd',
        'GdeF8gUqo3XbagGTnSuEZiSGuwUhCmbZJq',
      ],
    ];

    data.forEach(function (d) {
      var publicKey = PrivateKey.fromWIF(d[0]).toPublicKey();
      var address = Address.fromString(d[1]);
      address.hashBuffer.should.deep.equal(publicKey._getID());
    });
  });

  describe('#toString', function () {
    it('should print this known public key', function () {
      var hex =
        '031ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a';
      var pk = PublicKey.fromString(hex);
      pk.toString().should.equal(hex);
    });
  });

  describe('#inspect', function () {
    it('should output known uncompressed pubkey for console', function () {
      var pubkey = PublicKey.fromString(
        '041ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341'
      );
      pubkey
        .inspect()
        .should.equal(
          '<PublicKey: 041ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341, uncompressed>'
        );
    });

    it('should output known compressed pubkey for console', function () {
      var pubkey = PublicKey.fromString(
        '031ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a'
      );
      pubkey
        .inspect()
        .should.equal(
          '<PublicKey: 031ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a>'
        );
    });

    it('should output known compressed pubkey with network for console', function () {
      var privkey = PrivateKey.fromWIF(
        'cc1WuFikmenRcAybBtbq74BXhh1rUspd59fScmMNWuvLjQbowop7'
      );
      var pubkey = new PublicKey(privkey);
      pubkey
        .inspect()
        .should.equal(
          '<PublicKey: 0318a1cf4ba216b1215e8b2520c821a3a49d1751690530d672807f08a74cb6ff5b>'
        );
    });
  });

  describe('#validate', function () {
    it('should not have an error if pubkey is valid', function () {
      var hex =
        '031ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a';
      expect(function () {
        return PublicKey.fromString(hex);
      }).to.not.throw();
    });

    it('should throw an error if pubkey is invalid', function () {
      var hex =
        '041ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a0000000000000000000000000000000000000000000000000000000000000000';
      (function () {
        return PublicKey.fromString(hex);
      }.should.throw('Invalid y value for curve.'));
    });

    it('should throw an error if pubkey is invalid', function () {
      var hex =
        '041ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a00000000000000000000000000000000000000000000000000000000000000FF';
      (function () {
        return PublicKey.fromString(hex);
      }.should.throw('Invalid y value for curve.'));
    });

    it('should throw an error if pubkey is infinity', function () {
      (function () {
        return new PublicKey(Point.getG().mul(Point.getN()));
      }.should.throw('Point cannot be equal to Infinity'));
    });
  });
});
