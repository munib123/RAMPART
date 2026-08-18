# CrossVul Fix Pair: Improper Access Control in javascript
**Pair ID:** 2279_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2279_1`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```javascript
Lines 1-27 of the vulnerable file.

var Hapi = require('hapi');

var server = Hapi.createServer('127.0.0.1', 8000);

// Add Crumb plugin

server.pack.require('../', { restful: true }, function(err) {
    if (err) throw err;
});

server.route([

    // a "crumb" cookie gets set with any request when not using views

    {
        method: 'GET',
        path: '/generate',
        handler: function(request) {
            // return crumb if desired
            request.reply('{ "crumb": ' + request.plugins.crumb + ' }');
        }
    },

    // request header "X-CSRF-Token" with crumb value must be set in request for this route

    {
        method: 'PUT',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,7 +4,7 @@
 
 // Add Crumb plugin
 
-server.pack.require('../', { restful: true }, function(err) {
+server.pack.register({ plugin: require('../'), options: { restful: true } }, function(err) {
     if (err) throw err;
 });
 
```
