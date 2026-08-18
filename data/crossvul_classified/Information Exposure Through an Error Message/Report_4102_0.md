# CrossVul Fix Pair: Generation of Error Message Containing Sensitive Information in javascript
**Pair ID:** 4102_0
**Vulnerability Class:** Information Exposure Through an Error Message
**CWE:** CWE-209
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4102_0`)

## Vulnerability Information & PoC

## Description
Generation of Error Message Containing Sensitive Information - The sensitive information may be valuable information on its own (such as a password), or it may be useful for launching other, more serious attacks.

## Vulnerable Code
```javascript
Lines 1-26 of the vulnerable file.

var RestClient = require('rest-facade').Client;
var Promise = require('bluebird');
var ArgumentError = require('rest-facade').ArgumentError;

var utils = require('./utils');

var Auth0RestClient = function(resourceUrl, options, provider) {
  if (resourceUrl === null || resourceUrl === undefined) {
    throw new ArgumentError('Must provide a Resource Url');
  }

  if ('string' !== typeof resourceUrl || resourceUrl.length === 0) {
    throw new ArgumentError('The provided Resource Url is invalid');
  }

  if (options === null || typeof options !== 'object') {
    throw new ArgumentError('Must provide options');
  }

  this.options = options;
  this.provider = provider;
  this.restClient = new RestClient(resourceUrl, options);

  this.wrappedProvider = function(method, args) {
    if (!this.provider) {
      return this.restClient[method].apply(this.restClient, args);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,6 +3,7 @@
 var ArgumentError = require('rest-facade').ArgumentError;
 
 var utils = require('./utils');
+var SanitizedError = require('./errors').SanitizedError;
 
 var Auth0RestClient = function(resourceUrl, options, provider) {
   if (resourceUrl === null || resourceUrl === undefined) {
@@ -16,6 +17,9 @@
   if (options === null || typeof options !== 'object') {
     throw new ArgumentError('Must provide options');
   }
+
+  options.errorCustomizer = options.errorCustomizer || SanitizedError;
+  options.errorFormatter = options.errorFormatter || { message: 'message', name: 'error' };
 
   this.options = options;
   this.provider = provider;
```
