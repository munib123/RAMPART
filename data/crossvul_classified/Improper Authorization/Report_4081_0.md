# CrossVul Fix Pair: Improper Authorization in javascript
**Pair ID:** 4081_0
**Vulnerability Class:** Improper Authorization
**CWE:** CWE-285
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4081_0`)

## Vulnerability Information & PoC

## Description
Improper Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```javascript
Lines 1-41 of the vulnerable file.

var jwt = require('jsonwebtoken');
var UnauthorizedError = require('./errors/UnauthorizedError');
var unless = require('express-unless');
var async = require('async');
var set = require('lodash.set');

var DEFAULT_REVOKED_FUNCTION = function(_, __, cb) { return cb(null, false); };

function isFunction(object) {
  return Object.prototype.toString.call(object) === '[object Function]';
}

function wrapStaticSecretInCallback(secret){
  return function(_, __, cb){
    return cb(null, secret);
  };
}

module.exports = function(options) {
  if (!options || !options.secret) throw new Error('secret should be set');

  var secretCallback = options.secret;

  if (!isFunction(secretCallback)){
    secretCallback = wrapStaticSecretInCallback(secretCallback);
  }

  var isRevokedCallback = options.isRevoked || DEFAULT_REVOKED_FUNCTION;

  var _requestProperty = options.userProperty || options.requestProperty || 'user';
  var _resultProperty = options.resultProperty;
  var credentialsRequired = typeof options.credentialsRequired === 'undefined' ? true : options.credentialsRequired;

  var middleware = function(req, res, next) {
    var token;

    if (req.method === 'OPTIONS' && req.headers.hasOwnProperty('access-control-request-headers')) {
      var hasAuthInAccessControl = !!~req.headers['access-control-request-headers']
                                    .split(',').map(function (header) {
                                      return header.trim();
                                    }).indexOf('authorization');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,6 +18,9 @@
 
 module.exports = function(options) {
   if (!options || !options.secret) throw new Error('secret should be set');
+
+  if (!options.algorithms) throw new Error('algorithms should be set');
+  if (!Array.isArray(options.algorithms)) throw new Error('algorithms must be an array');
 
   var secretCallback = options.secret;
 
```
