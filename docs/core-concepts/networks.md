# Networks

GoBytecore provides support for the main GoByte network as well as for `testnet3`, the current test blockchain. We encourage the use of `Networks.livenet` and `Networks.testnet` as constants. Note that the library sometimes may check for equality against this object. Please avoid creating a deep copy of this object.

The `Network` namespace has a function, `get(...)` that returns an instance of a `Network` or `undefined`. The only argument to this function is some kind of identifier of the network: either its name, a reference to a Network object, or a number used as a magic constant to identify the network (for example, the value `0x26` that gives GoByte addresses the distinctive `'G'` at its beginning on livenet, is a `0x70` for testnet).

## Regtest

The regtest network is useful for development as it's possible to programmatically and instantly generate blocks for testing. It's currently supported as a variation of testnet. Here is an example of how to use regtest with the GoBytecore Library:

```js
// Standard testnet
> gobytecore.Networks.testnet.networkMagic;
<Buffer d1 2b b3 7a>
```

```js
// Enabling testnet to use the regtest port and magicNumber
> gobytecore.Networks.enableRegtest();
> gobytecore.Networks.testnet.networkMagic;
<Buffer a1 b3 d5 7b>
```

## Setting the Default Network

Most projects will only need to work with one of the networks. The value of `Networks.defaultNetwork` can be set to `Networks.testnet` if the project will need to only to work on testnet (the default is `Networks.livenet`).

## Network constants

The functionality of testnet and livenet is mostly similar (except for some relaxed block validation rules on testnet). They differ in the constants being used for human representation of base58 encoded strings. These are sometimes referred to as "version" constants.

```javascript
var livenet = new Network();
_.extend(livenet, {
  name: 'livenet',
  alias: 'mainnet',
  pubkeyhash: 0x26,
  privatekey: 0xC6,
  scripthash: 0x0A,
  xpubkey: 0x488b21e,
  xprivkey: 0x488ade4,
  networkMagic: 0x1ab2c3d4,
  port: 12455,
});

var testnet = new Network();
_.extend(testnet, {
  name: 'testnet',
  alias: 'testnet',
  pubkeyhash: 0x70,
  privatekey: 0xf0,
  scripthash: 0x14,
  xpubkey: 0x43587cf,
  xprivkey: 0x04358394,
  port: 13455,
});
```
