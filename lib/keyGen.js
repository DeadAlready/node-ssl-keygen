/* 
 * Copyright 2012 Karl Düüna <karl.dyyna@gmail.com> All rights reserved.
 */
'use strict';

var fs = require('fs');
var mkdirp = require('mkdirp');
var path = require('path');
var foldermap = require('foldermap');
var utils = require('./utils');
var crypto = require('crypto');
var exec = require('child_process').exec;

var serial = ~~(Math.random()*10000)%100;

function KeyGen(options){
  if(this instanceof KeyGen === false){
    return new KeyGen(options);
  }
  
  if(!options)
    options = {};
  
  // Give possibility to include bunyan logger
  if(!options.log){
    this.log = function(type, log){
      console.log(log);
    }
  } else {
    this.log = function(type, log){
      options.log[type](log);
    }
  }
  
  this.subj = {
    C:'EE',
    ST:'Harjumaa',
    L:'Tallinn',
    O:'Example',
    OU:'Unit',
    emailAddress:'admin@email.address'
  };
  
  if(options.subj){
    utils.extend(this.subj, options.subj);
  }
  
  this.size = options.size || 4096;
  
  this.root = options.root || process.cwd() + path.sep;
  this.folder = this.root + utils.fixPath(options.folder || 'certs');
  
  Object.defineProperty(this, '_cC',{value:utils.wrapCleanCallback(this)});
  
}

module.exports = KeyGen;

/**
 * Function returning an object containing absolute paths to keys
 * 
 * @param {String} name name of key
 * @param {Boolean} [csr=false] wheter to return csr path
 * @return {Object}
 */
KeyGen.prototype._keyPair = function _keyPair(name, csr){
  
  var pair = {
    key: this.folder + name + '.key',
    crt: this.folder + name + '.crt'
  };
  if(csr){
    pair.csr = this.folder + name + '.csr';
  }
  return pair;
}

/**
 * Function returning the -subj part of openssl commands
 * 
 * @param {String} name name of the certificate
 * @return {String}
 */
KeyGen.prototype._subject = function _subject(name){
  var subject = '';
  for(var i in this.subj){
    subject += '/' + i + '=' + this.subj[i];
  }
  
  subject += '/CN='+ _subjectName(name);
  return subject;
}

/**
 * Function for creating a RSA key
 * 
 * @param {String} name name of key
 * @param {Boolean} [force=false] whether to force the creation
 * @param {Function} callback
 */
KeyGen.prototype.createKey = function createKey(name, force, callback){
  if(force instanceof Function){
    callback = force;
    force = false;
  }
  this.log('debug',(force ? 'Force creating' : 'Creating') + ' new key named - ' + name);
  
  var pair = this._keyPair(name);
  var self = this;
  var command = utils.stringify('openssl genrsa -out :name: :size:', {name:pair.key, size:self.size});
  
  fs.stat(pair.key, function(err, stat){
    if(err){
      _createPath(pair.key, self._cC(callback, function(){
        exec(command, self._cC(callback, function(){
          _returnMap(callback, pair.key, true);
        }));
      }));
    } else if(force){
      exec(command, self._cC(callback, function(){
        _returnMap(callback, pair.key, true);
      }));
    } else {
      _returnMap(callback, pair.key);
    }
  });
}

/**
 * Function for creating a cert
 * 
 * @param {String} name name of key
 * @param {Object} [ca=false] ca information
 * @param {Boolean} [force=false] whether to force the creation
 * @param {Function} callback
 */
KeyGen.prototype.createCert = function createCert(name, ca, force, callback){
  if(ca instanceof Function){
    callback = ca;
    force = false;
    ca = false;
  } else if(force instanceof Function){
    callback = force;
    force = false;
  }
  this.log('debug',(force ? 'Force creating' : 'Creating') + ' new key named - ' + name + (ca ? ' using CA' : ''));
  
  var pair = this._keyPair(name);
  var self = this;
  fs.stat(pair.crt,function(err,stat){
    if(err || force){
      if(ca){
        self.createSignRequest(name, self._cC(callback, function(){
          self._sign(name, ca, force, self._cC(callback, function(){
            _returnMap(callback, pair.crt, true);
          }));
        }));
      } else {
        self._sign(name, ca, force, self._cC(callback, function(crt){
          callback(null, crt);
        }));
      }
    } else {
      _returnMap(callback, pair.crt);
    }
  });
}

/**
 * Function for creating a certificate signing request
 * 
 * @param {String} name name of key
 * @param {Function} callback
 */
KeyGen.prototype.createSignRequest = function createSignRequest(name, callback){
  this.log('debug','Create sign request for - ' + name);
  
  var pair = this._keyPair(name, true);
  pair.subj = this._subject(name);
  this.createKey(name, this._cC(callback, function(){
    exec(utils.stringify('openssl req -new -subj :subj: -key :key: -out :csr:', pair), self._cC(callback));
  }));
}

/**
 * Function for creating a cert from key by either signing a request or key
 * 
 * @param {String} name name of key
 * @param {Object} [ca=false] ca information
 * @param {Boolean} [force=false] whether to force the creation
 * @param {Function} callback
 */
KeyGen.prototype._sign = function sign(name, ca, force, callback){
  
  this.log('debug','_sign');
  if(ca instanceof Function){
    callback = ca;
    force = false;
    
    this.signCA(name, force, callback);
  } else if(force instanceof Function) {
    callback = force;
    force = false;
    
    if(ca === false){
      this.signCA(name, force, callback);
    } else {
      this.signRequest(name, ca, callback);
    }
  }
  if(ca === false){
    this.signCA(name, force, callback);
  } else {
    this.signRequest(name, ca, force, callback);
  }
}

/**
 * Function for creating a CA cert from key
 * 
 * @param {String} name name of key
 * @param {Boolean} [force=false] whether to force the creation
 * @param {Function} callback
 */
KeyGen.prototype.signCA = function signCA(name, force, callback){
  
  if(force instanceof Function){
    callback = force;
    force = false;
  }
  
  this.log('debug',(force ? 'Force signing' : 'Sign') + ' CA cert named - ' + name);
  
  var pair = this._keyPair(name);
  pair.subj = this._subject(name);
  
  fs.stat(pair.crt, function(err, stat){
    if(err || force){
      exec(utils.stringify('openssl req -new -subj :subj: -x509 -days 365 -key :key: -out :crt:', pair), self._cC(callback, function(){
        _returnMap(callback, pair.crt, true);
      }));
    } else {
      _returnMap(callback, pair.crt, false);
    }
  });
  
}

/**
 * Function for signing a certificate signing request
 * 
 * @param {String} name name of key
 * @param {Object} ca ca information
 * @param {Boolean} [force=false] whether to force the creation
 * @param {Function} callback
 */
KeyGen.prototype.signRequest = function signRequest(name, ca, force, callback){
  if(force instanceof Function){
    callback = force;
    force = false;
  }
  
  this.log('debug',(force ? 'Force signing' : 'Sign') + ' request named - ' + name);
  var pair = this._keyPair(name, true);
  
  var opts = {
    csr: pair.csr,
    crt: pair.crt,
    caCert: ca.crt._path,
    caKey: ca.key._path,
    serial: '0' + (serial++)
  }
  
  fs.stat(pair.crt, function(err, stats){
    if(err || force){
      exec(utils.stringify('openssl x509 -req -days 365 -in :csr: -CA :caCert: -CAkey :caKey: -set_serial :serial: -out :crt:', opts), self._cC(callback, function(){
        _returnMap(callback, pair.crt, true);
      }));
    } else {
      _returnMap(callback, pair.crt, false);
    }
  });
}

/**
 * Function for creating a self signed CA
 * 
 * @param {String} name certificate name
 * @param {Boolean} [force=false] whether to force the creation
 * @param {Function} callback
 */
KeyGen.prototype.createCA = function createCA(name, force, callback){
  
  this.log('debug','createCA');
  
  var self = this;
  self.createKey(name, force, self._cC(callback, function(key){
    self._sign(name, false, key._created, self._cC(callback, function(crt){
      callback(null,{key:key,crt:crt});
    }));
  }));
}

/**
 * Function for creating a self signed keypair
 * 
 * @param {String} name certificate name
 * @param {Object} ca object containing ca information
 * @param {Function} callback
 */
KeyGen.prototype.createSelfSigned = function createSelfSigned(name, ca, callback){
  this.log('debug','createSelfSigned - ' + name);
  var self = this;
  self.createKey(name, ca.key._created, self._cC(callback, function(key){
    self.createCert(name, ca, key._created, self._cC(callback, function(crt){
      callback(null, {key:key, crt:crt});
    }));
  }));
}

/**
 * Function creating folder structure for key
 * 
 * @param {String} name name of key
 * @param {Function} callback
 */
function _createPath(name, callback){
  mkdirp(path.dirname(name), callback);
}

/**
 * Function creating subject name for -subj
 * 
 * @param {String} name name of key
 */
function _subjectName(name){
  return name.replace(/\//g,'_') + '-' + Date.now();
}

/**
 * Function for returning foldermap.mapTree object to callback
 * 
 * @param {Function} callback function to call with result
 * @param {String|String[]} file string or object or array containing files to map
 * @param {Boolean} [created=false] Whether to mark objects as created
 */
function _returnMap(callback, file, created){
  if(typeof file === 'string'){
    var map = foldermap.mapTreeSync(file);
    Object.defineProperty(map, '_created', {value:created});
  } else {
    var map = {};
    for(var i in file){
      map[i] = foldermap.mapTreeSync(file[i]);
      Object.defineProperty(map[i], '_created', {value:created});
    }
  }
  callback(null, map)
}