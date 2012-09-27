'use strict';

var KeyChain = require('./lib/keyChain');
var KeyGen = require('./lib/keyGen');

module.exports.KeyChain = KeyChain;
module.exports.KeyGen = KeyGen;

module.exports.createKeyChain = function(options){
  return new KeyChain(options);
}

module.exports.createKeyGen = function(options){
  return new KeyGen(options);
}

