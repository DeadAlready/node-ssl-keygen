/* 
 * Copyright 2012 Karl Düüna <karl.dyyna@gmail.com> All rights reserved.
 */
'use strict';

var ssl = require('../index');
var vows = require('vows');
var assert = require('assert');
var fs = require('fs');
var path = require('path');
var rimraf = require('rimraf');
var spec = require('vows/lib/vows/reporters/spec');

var KeyGen = ssl.KeyGen;
var keyGen = new KeyGen();
var folder = process.cwd() + path.sep + 'certs' + path.sep;
var Keys = {};

function assertFile(name, type, created){
  return function(err, key){
    assert.equal(err, null);
    assert.notDeepEqual(key, {
      _created: created,
      _name: name + '.' + type,
      _base: name,
      _ext: type,
      _type: 'file',
      _path: folder + name + '.' + type
    });

    fs.stat(keyGen._keyPair(name)[type], function(err, stats){
      assert.equal(err, null);
    });
  }
}

function assertPair(name, keyCreated, crtCreated){
  return function(err, pair){
    assertFile(name, 'key', keyCreated)(err, pair.key);
    assertFile(name, 'crt', crtCreated)(err, pair.crt);
  }
}

function _findCWD(module){
  var lvl = 0;
  var p = path.relative(process.cwd(), require.resolve(module)).split(path.sep);
  if(p[0] === '..'){
    lvl++;
  }
  var i = 0;
  while(p[i] === '..'){
    lvl++;
  }
  var folderMapCWD = process.cwd() + path.sep;
  for(var i = 0; i <= lvl; i++){
    folderMapCWD += '..' + path.sep;
  }
  return path.resolve(folderMapCWD);
}

// Create a Test Suite
vows.describe('SSL-KeyGen').addBatch({
  'RimRaf':{
    topic:function(){
      rimraf(folder,this.callback);
    },
    'testfolder removed':function(err){
      assert.equal(err, null);
    }
  }
}).addBatch({
  'Foldermap':{
    topic: function(){
      require('child_process').exec('npm test foldermap', {cwd: _findCWD('foldermap') }, this.callback);
    },
    'foldermap working':function(err, stdout, stderr){
      assert.equal(err, null);
      assert.equal(stderr, null);
    }
  }
}).addBatch({
  'KeyGen': {
    topic: new(KeyGen),
    '_keyPair no csr': {
      topic: function(){
        return keyGen._keyPair('test');
      },
      'keyPair value': function(pair){
        assert.deepEqual(pair, {
          key: folder + 'test.key',
          crt: folder + 'test.crt'
        });
      }
    },
    '_keyPair with csr': {
      topic: function(){
        return keyGen._keyPair('test', true);
      },
      'keyPair value': function(pair){
        assert.deepEqual(pair, {
          key: folder + 'test.key',
          crt: folder + 'test.crt',
          csr: folder + 'test.csr'
        });
      }
    },
    'createKey no forcing no previous': {
      topic: function(){
        keyGen.createKey('test', this.callback);
      },
      'key was created': assertFile('test', 'key', true),
      'with previous':{
        topic: function(){
          keyGen.createKey('test', this.callback);
        },
        'key was found': assertFile('test', 'key', false)
      }
    },
    'createKey forcing': {
      topic: function(){
        keyGen.createKey('test2', true, this.callback);
      },
      'key was found': assertFile('test2', 'key', true),
      'with previous':{
        topic: function(){
          keyGen.createKey('test2', true, this.callback);
        },
        'key was found': assertFile('test2', 'key', true)
      }
    }
  }
}).addBatch({
  'createCert':{
    topic:function(){
      keyGen.createCert('test2', this.callback);
    },
    'cert was created': assertFile('test2', 'crt', true),
    'with previous':{
      topic:function(){
        keyGen.createCert('test2', this.callback);
      },
      'cert was created': assertFile('test2', 'crt', false)
    },
    'with forcing':{
      topic:function(){
        keyGen.createCert('test2', false, true, this.callback);
      },
      'cert was created': assertFile('test2', 'crt', true)
    }
  }
}).addBatch({
  'createCA no forcing' : {
    topic: function(){
      keyGen.createCA('test3', false, this.callback);
    },
    'key was found': assertPair('test3', true, true),
    'with previous':{
      topic: function(){
        keyGen.createCA('test3', false, this.callback);
      },
      'key was found': assertPair('test3', false, false)
    }
  },
  'createCA forcing' : {
    topic: function(){
      keyGen.createCA('test4', true, this.callback);
    },
    'key was found': assertPair('test4', true, true),
    'with previous':{
      topic: function(){
        var callback = this.callback;
        keyGen.createCA('test4', true, function(err, keys){
          Keys = keys;
          callback.apply(this, arguments);
        });
      },
      'key was found': assertPair('test4', true, true)
    }
  }
}).addBatch({
  'createSignedRequest with separate functions': {
    topic: function(){
      var callback = this.callback;
      keyGen.createKey('test6', function(){
        keyGen.createSignRequest('test6', callback);
      });
    },
    'signrequest was created': function(err){
      assert.equal(err, null);
    },
    'sign no forcing': {
      topic: function(){
        keyGen.signRequest('test6', Keys, false, this.callback);
      },
      'key was signed': assertFile('test6', 'crt', true),
      'resign no forceing':{
        topic:function(){
          keyGen.signRequest('test6', Keys, false, this.callback);
        },
        'key was found': assertFile('test6', 'crt', false)
      }
    }
  },
  'createCert':{
    topic:function(){
      var callback = this.callback;
      keyGen.createKey('test7', function(){
        keyGen.createCert('test7', Keys, callback);
      });
    },
    'cert was created': assertFile('test7', 'crt', true),
    'with previous, with forcing':{
      topic:function(){
        keyGen.createCert('test7', Keys, true, this.callback);
      },
      'cert was created': assertFile('test7', 'crt', true)
    }
  },
  'createSelfSigned':{
    topic:function(){
      keyGen.createSelfSigned('test5', Keys, this.callback);
    },
    'self signed pair created': assertPair('test5', true, true),
    'with previous and forcing':{
      topic:function(){
        keyGen.createSelfSigned('test5', Keys, this.callback);
      },
      'self signed pair created': assertPair('test5', true, true)
    }
  }
}).run({reporter:spec}, function(){
  rimraf(folder,function(){});
}); // Run it


