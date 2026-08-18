# CrossVul Fix Pair: Improper Access Control in javascript
**Pair ID:** 2279_6
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2279_6`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```javascript
Lines 10-50 of the vulnerable file.

var internals = {};


// Test shortcuts

var expect = Lab.expect;
var before = Lab.before;
var after = Lab.after;
var describe = Lab.experiment;
var it = Lab.test;


describe('Crumb', function () {

    it('validates crumb with X-CSRF-Token header', function (done) {

        var options = {
            views: {
                path: __dirname + '/templates',
                engines: {
                    html: 'handlebars'
                }
            }
        };

        var server = new Hapi.Server(options);

        server.route([
            {
                method: 'GET', path: '/1', handler: function (request, reply) {

                    expect(request.plugins.crumb).to.exist;
                    expect(request.server.plugins.crumb.generate).to.exist;

                    return reply.view('index', {
                        title: 'test',
                        message: 'hi'
                    });
                }
            },
            {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,7 +27,7 @@
             views: {
                 path: __dirname + '/templates',
                 engines: {
-                    html: 'handlebars'
+                    html: require('handlebars')
                 }
             }
         };
@@ -97,7 +97,7 @@
 
         ]);
 
-        server.pack.require('../', { restful: true, cookieOptions: { isSecure: true } }, function (err) {
+        server.pack.register({plugin: require('../'), options: { restful: true, cookieOptions: { isSecure: true } } }, function (err) {
 
             expect(err).to.not.exist;
             server.inject({ method: 'GET', url: '/1' }, function (res) {
```
