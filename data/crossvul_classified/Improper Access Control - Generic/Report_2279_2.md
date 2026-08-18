# CrossVul Fix Pair: Improper Access Control in javascript
**Pair ID:** 2279_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2279_2`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```javascript
Lines 1-27 of the vulnerable file.

var Hapi = require('hapi');

var serverOptions = {
    views: {
        path: __dirname + '/templates',
        engines: {
            html: 'handlebars'
        }
    }
};

var server = new Hapi.Server('127.0.0.1', 8000, serverOptions);

server.pack.require('../', { cookieOptions: { isSecure: false } }, function (err) {
    if (err) throw err;
});

server.route({
    method: 'get',
    path: '/',
    handler: function (request, reply) {
        return reply.view('index', { title: 'test', message: 'hi' });
    }
});

server.route({
    method: 'post',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,14 +4,14 @@
     views: {
         path: __dirname + '/templates',
         engines: {
-            html: 'handlebars'
+            html: require('handlebars')
         }
     }
 };
 
 var server = new Hapi.Server('127.0.0.1', 8000, serverOptions);
 
-server.pack.require('../', { cookieOptions: { isSecure: false } }, function (err) {
+server.pack.register({ plugin: require('../'), options: { cookieOptions: { isSecure: false } } }, function (err) {
     if (err) throw err;
 });
 
```
