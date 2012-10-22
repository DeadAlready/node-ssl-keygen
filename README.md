[ssl-keygen](https://github.com/DeadAlready/node-ssl-keygen) is a wrapper for creating SSL certs.

# Installation

    $ npm install ssl-keygen

# Usage

ssl-keygen is a utility wrapper for creating SSL keys and certs using OpenSSL.

## API

The module exports the following functions and objects

+ KeyGen: *Handle to the ssl-keygen constructor
+ createKeyGen(options): *function returning a new ssl-keygen with specified options


### KeyGen Options

The following options are available:

+ log: *Bunyan logger or boolean, will default to false
+ root: *Project root folder will default to process.cwd()
+ folder: *The certs folder name default to 'certs'
+ size: *The size used when creating keys, default 4096
+ subj: *The subj used when creating certificate requests

Subj default:

    {
      C:'EE',
      ST:'Harjumaa',
      L:'Tallinn',
      O:'Example',
      OU:'Unit',
      emailAddress:'admin@email.address'
    }

## KeyGen API

The following functions are available on the KeyGen object

### createCA

Function for creating a self signed CA

+ @param {String} name certificate name
+ @param {Boolean} [force=false] whether to force the creation
+ @param {Function} callback

### createCert

Function for creating a cert from a key file

+ @param {String} name name of key
+ @param {Object} [ca=false] ca information, if none given a CA cert will be created
+ @param {Boolean} [force=false] whether to force the creation
+ @param {Function} callback

### createKey

Function for creating a RSA key

+ @param {String} name name of key
+ @param {Boolean} [force=false] whether to force the creation
+ @param {Function} callback

### createSelfSigned

Function for creating a self signed keypair

+ @param {String} name certificate name
+ @param {Object} ca object containing ca information
+ @param {Boolean} [force=false] force creation of keys?
+ @param {Function} callback

### createSignRequest

Function for creating a certificate signing request

+ @param {String} name name of key
+ @param {Function} callback

### signCA

Function for creating a CA cert from key

+ @param {String} name name of key
+ @param {Boolean} [force=false] whether to force the creation
+ @param {Function} callback

### signRequest

Function for signing a certificate signing request

+ @param {String} name name of key
+ @param {Object} ca ca information
+ @param {Boolean} [force=false] whether to force the creation
+ @param {Function} callback

### _keyPair

Utility function returning an object containing absolute paths to keyfiles

+ @param {String} name name of key
+ @param {Boolean} [csr=false] wheter to return csr path
@return {Object}

### _subject

Function returning the -subj part of openssl commands

+ @param {String} name name of the certificate
@return {String}

### _sign

Function for creating a cert from key by either signing a request or key

+ @param {String} name name of key
+ @param {Object} [ca=false] ca information, if none given a CA cert will be created
+ @param {Boolean} [force=false] whether to force the creation
+ @param {Function} callback

## License

The MIT License (MIT)
Copyright (c) 2012 Karl Düüna

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.