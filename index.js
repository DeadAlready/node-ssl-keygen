/* 
 * Copyright 2012 Karl Düüna <karl.dyyna@gmail.com> All rights reserved.
 */
'use strict';

var KeyGen = require('./lib/keyGen');

module.exports.KeyGen = KeyGen;

module.exports.createKeyGen = function(options){
  return new KeyGen(options);
}

