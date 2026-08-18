# CrossVul Fix Pair: Improper Handling of Case Sensitivity in javascript
**Pair ID:** 697_0
**Vulnerability Class:** Improper Handling of Case Sensitivity
**CWE:** CWE-178
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `697_0`)

## Vulnerability Information & PoC

## Description
Improper Handling of Case Sensitivity - Improperly handled case sensitive data can lead to several possible consequences, including: case-insensitive passwords reducing the size of the key space, making brute force attacks easier bypassi...

## Vulnerable Code
```javascript
Lines 3-43 of the vulnerable file.

var httpLogger = log4js.getLogger("http");
var settings = require('../../utils/Settings');
var hooks = require('ep_etherpad-lite/static/js/pluginfw/hooks');
var ueberStore = require('../../db/SessionStore');
var stats = require('ep_etherpad-lite/node/stats');
var sessionModule = require('express-session');
var cookieParser = require('cookie-parser');

//checks for basic http auth
exports.basicAuth = function (req, res, next) {
  var hookResultMangle = function (cb) {
    return function (err, data) {
      return cb(!err && data.length && data[0]);
    }
  }

  var authorize = function (cb) {
    // Do not require auth for static paths and the API...this could be a bit brittle
    if (req.path.match(/^\/(static|javascripts|pluginfw|api)/)) return cb(true);

    if (req.path.indexOf('/admin') != 0) {
      if (!settings.requireAuthentication) return cb(true);
      if (!settings.requireAuthorization && req.session && req.session.user) return cb(true);
    }

    if (req.session && req.session.user && req.session.user.is_admin) return cb(true);

    hooks.aCallFirst("authorize", {req: req, res:res, next:next, resource: req.path}, hookResultMangle(cb));
  }

  var authenticate = function (cb) {
    // If auth headers are present use them to authenticate...
    if (req.headers.authorization && req.headers.authorization.search('Basic ') === 0) {
      var userpass = new Buffer(req.headers.authorization.split(' ')[1], 'base64').toString().split(":")
      var username = userpass.shift();
      var password = userpass.join(':');

      if (settings.users[username] != undefined && settings.users[username].password === password) {
        settings.users[username].username = username;
        req.session.user = settings.users[username];
        return cb(true);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,7 +20,7 @@
     // Do not require auth for static paths and the API...this could be a bit brittle
     if (req.path.match(/^\/(static|javascripts|pluginfw|api)/)) return cb(true);
 
-    if (req.path.indexOf('/admin') != 0) {
+    if (req.path.toLowerCase().indexOf('/admin') != 0) {
       if (!settings.requireAuthentication) return cb(true);
       if (!settings.requireAuthorization && req.session && req.session.user) return cb(true);
     }
```
