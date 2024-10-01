# This library has been deprecated. Please refer to the current library at https://github.com/Adscore/nodejs-common
# @variably/adscore-node

Official API

- Package version: 0.0.1

## Requirements.

NodeJS 8.11.4+

### NodeJS

To install this package you must have [NodeJS](https://nodejs.org/en/download/package-manager/) installed, please follow those instructions for your OS before attempting to use this package.

### NPM

Install via [NPM](https://www.npmjs.com/get-npm) (easiest method).

```sh
npm install --save @variably/adscore-node
```

Then import the package:
```javascript
const adscoreNode = require('@variably/adscore-node');
```

## Basic Usage

Please follow the installation procedure and then you may run the following:

```javascript
const adscoreNode = require('@variably/adscore-node');

const signatureExpiry = 3600; // in seconds, the length of time before the signature is considered expired
const signatureKey = adscoreNode.keyDecode('<base64 adscore validation key>');

const ipA = ''; // user ip
const ipB = ''; // another ip (likely situation is ipv4 and ipv6)
const ipAddresses = [
  ipA,
  ipB
];
const userAgent = ''; // user agent
const signature = ''; // adscore signature

const signRole = 'customer'; // standard signing role

const result = adscoreNode.verify({
  key: signatureKey, 
  expiry: signatureExpiry,

  signature,
  userAgent,
  ipAddresses,
  signRole
});
console.log('result', result);

/*
result {
  expired: true, // if present, the provided signature is expired

  error: '', // if present, the signature verification has raised an error

  score: , // integer score: [0, 3, 6, 9]
  verdict: '', // string verdict: ['ok', 'junk', 'proxy', 'bot']
  ipAddress: '', // ip address that matched this signature
  requestTime: , // time the signature was requested
  signatureTime: // time the signature was signed
}
*/
```

## Documentation For Authorization

 All endpoints require authorization, please see [adscore.com](https://adscore.com) for more information.


## Author

 Variably
