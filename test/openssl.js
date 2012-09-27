/* 
 * Copyright 2012 Karl Düüna <karl.dyyna@gmail.com> All rights reserved.
 */
'use strict';

require('child_process').exec('openssl', function(err, stdout, stderr){
  if(err){
    throw new Error('OpenSSL required for this module');
  }
});