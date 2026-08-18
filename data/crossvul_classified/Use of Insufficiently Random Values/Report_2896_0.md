# CrossVul Fix Pair: Use of Insufficiently Random Values in javascript
**Pair ID:** 2896_0
**Vulnerability Class:** Use of Insufficiently Random Values
**CWE:** CWE-330
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2896_0`)

## Vulnerability Information & PoC

## Description
Use of Insufficiently Random Values - When product generates predictable values in a context requiring unpredictability, it may be possible for an attacker to guess the next value that will be generated, and use this guess to impersona...

## Vulnerable Code
```javascript
Lines 1-34 of the vulnerable file.

/*!
 * socket.io-node
 * Copyright(c) 2011 LearnBoost <dev@learnboost.com>
 * MIT Licensed
 */

/**
 * Module dependencies.
 */

var fs = require('fs')
  , url = require('url')
  , tty = require('tty')
  , util = require('./util')
  , store = require('./store')
  , client = require('socket.io-client')
  , transports = require('./transports')
  , Logger = require('./logger')
  , Socket = require('./socket')
  , MemoryStore = require('./stores/memory')
  , SocketNamespace = require('./namespace')
  , Static = require('./static')
  , EventEmitter = process.EventEmitter;

/**
 * Export the constructor.
 */

exports = module.exports = Manager;

/**
 * Default transports.
 */

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,6 +11,7 @@
 var fs = require('fs')
   , url = require('url')
   , tty = require('tty')
+  , crypto = require('crypto')
   , util = require('./util')
   , store = require('./store')
   , client = require('socket.io-client')
@@ -139,6 +140,8 @@
     self.emit('connection', conn);
   });
 
+  this.sequenceNumber = Date.now() | 0;
+ 
   this.log.info('socket.io started');
 };
 
@@ -702,9 +705,12 @@
  * @api private
  */
 
-Manager.prototype.generateId = function () {
-  return Math.abs(Math.random() * Math.random() * Date.now() | 0).toString()
-    + Math.abs(Math.random() * Math.random() * Date.now() | 0).toString();
+Manager.prototype.generateId = function (data) {
+  var rand = new Buffer(15); // multiple of 3 for base64
+  this.sequenceNumber = (this.sequenceNumber + 1) | 0;
+  rand.writeInt32BE(this.sequenceNumber, 11);
+  crypto.randomBytes(12).copy(rand);
+  return rand.toString('base64').replace(/\//g, '_').replace(/\+/g, '-');
 };
 
 /**
@@ -752,7 +758,7 @@
     if (err) return error(err);
 
     if (authorized) {
-      var id = self.generateId()
+      var id = self.generateId(newData || handshakeData)
         , hs = [
               id
             , self.enabled('heartbeats') ? self.get('heartbeat timeout') || '' : ''
@@ -872,9 +878,9 @@
   if (this.get('authorization')) {
     var self = this;
 
-    this.get('authorization').call(this, data, function (err, authorized) {
+    this.get('authorization').call(this, data, function (err, authorized, newData) {
       self.log.debug('client ' + authorized ? 'authorized' : 'unauthorized');
-      fn(err, authorized);
+      fn(err, authorized, newData);
     });
   } else {
     this.log.debug('client authorized');
```
