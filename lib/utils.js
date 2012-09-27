'use strict';

var path = require('path');

/**
 * A extends B
 *
 * util.inherits works only with objects derived from Object
 *
 * @return {Object} Extended object
 */
function extend(a, b, noClone) { // A extends B
  a = a || {};
  
  if(typeof a !== 'object' || typeof a.length !== 'undefined'){
    return b;
  }
  
  if(typeof b !== 'object'){
    return b;
  }
  
  if(!noClone){
    a = clone(a);
  }
  
  var bk = Object.keys(b);
  for(var i = 0, c = bk.length; i < c; i++){
    var key = bk[i];
    if (!a.hasOwnProperty(key) || !(typeof b[key] === 'object' && typeof b[key].length === 'undefined') && typeof b[key] !== 'function') { // Simple types
      a[key] = b[key];
    } else { // Complex types
      a[key] = extend(a[key], b[key]);
    }
  }

  return a;
};

/**
 * Function for creating a clone of an object
 * 
 * @param o {Object}  object to clone
 * @return {Object}
 */
function clone(o){
  var c = {};
  var h = Object.keys(o);
  for(var i = 0, co = h.length; i < co; i++){
    c[h[i]] = o[h[i]];
  }
  return c;
}

/**
 * Function for appending path.sep to the end of string if necessary
 * 
 * @param string {String}
 * @return {String}
 */
function fixPath(string){
  if(string.length < 1){
    return string;
  }
  
  if(string.charAt(string.length-1) !== path.sep){
    string += path.sep;
  }
  return string;
}

/**
 * Function for replacing paramteres in a string with variables
 * 
 * @param string  {String} string with placeholders
 * @param params  {Object} object containing parameters
 * @param noError {Boolean} wheter to break on missing or corrupt values
 * @return {String}
 */
function stringify(string, params, noError) {
  var arr = string.split(':');
  var param;
  for(var i = 0, c = arr.length; i < c; i++) {
    param = arr[i];
    if(i % 2){
      if(!(typeof params[param] === 'string' || typeof params[param] === 'number')){
        if(!noError){
          throw new Error('Variable ' + param + ' not defined');
        }
      } else {
        arr[i] = params[param];
      }
    }
  }
  return arr.join('');
}

/**
 * Funciton for capitalizing the first letter of string
 * 
 * @param string {String} string to capitalize
 * @return {String}
 */
function capitalize(string){
  return string.charAt(0).toUpperCase() + string.slice(1);
}

/**
 * Function for wraping callback to handle errors
 * 
 * @param errorCallback {Function}  callback used upon error
 * @param callback      {Function}  callback used when no error
 */
function cleanCallback(errorCallback, callback){
  if(!callback){
    return function(err){ // remove other variables
      errorCallback(err);
    }
  }
  
  return function(err){
    if(err){
      errorCallback(err);
      return;
    }
    callback.apply(callback, Array.prototype.slice.call(arguments,1));
  }
}

module.exports = {
  extend: extend,
  clone: clone,
  fixPath: fixPath,
  stringify: stringify,
  capitalize: capitalize,
  cleanCallback: cleanCallback,
  cC: cleanCallback
}