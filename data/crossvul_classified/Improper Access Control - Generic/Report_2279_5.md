# CrossVul Fix Pair: Improper Access Control in javascript
**Pair ID:** 2279_5
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2279_5`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```javascript
Lines 10-50 of the vulnerable file.

// Declare internals

var internals = {};


// Test shortcuts

var expect = Lab.expect;
var before = Lab.before;
var after = Lab.after;
var describe = Lab.experiment;
var it = Lab.test;


describe('Crumb', function () {

    var options = {
        views: {
            path: __dirname + '/templates',
            engines: {
                html: 'handlebars'
            }
        }
    };

    it('returns view with crumb', function (done) {

        var server1 = new Hapi.Server(options);
        server1.route([
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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,7 +27,7 @@
         views: {
             path: __dirname + '/templates',
             engines: {
-                html: 'handlebars'
+                html: require('handlebars')
             }
         }
     };
@@ -81,10 +81,16 @@
 
                     return reply.view('index');
                 }
+            },
+            {
+                method: 'GET', path: '/7', handler: function (request, reply) {
+
+                    return reply(null).redirect('/1');
+                }
             }
         ]);
 
-        server1.pack.require('../', { cookieOptions: { isSecure: true } }, function (err) {
+        server1.pack.register({ plugin: require('../'), options: { cookieOptions: { isSecure: true } } }, function (err) {
 
             expect(err).to.not.exist;
             server1.inject({ method: 'GET', url: '/1' }, function (res) {
@@ -146,8 +152,15 @@
                                         var cookie = header[0].match(/crumb=([^\x00-\x20\"\,\;\\\x7F]*)/);
                                         expect(res.result).to.equal('<!DOCTYPE html><html><head><title></title></head><body><div><h1></h1><h2>' + cookie[1] + '</h2></div></body></html>');
 
-                                        done();
                                     });
+                                });
+
+                                server1.inject({method: 'GET', url: '/7'}, function(res) {
+
+                                    var cookie = res.headers['set-cookie'].toString();
+                                    expect(cookie).to.contain('crumb');
+
+                                    done();
                                 });
                             });
                         });
@@ -173,7 +186,7 @@
             }
         });
 
-        server2.pack.require('../', { cookieOptions: { isSecure: true }, addToViewContext: false }, function (err) {
+        server2.pack.register({ plugin: require('../'), options: { cookieOptions: { isSecure: true }, addToViewContext: false } }, function (err) {
 
             expect(err).to.not.exist;
             server2.inject({ method: 'GET', url: '/1' }, function (res) {
@@ -200,7 +213,7 @@
             }
         });
 
-        server3.pack.require('../', null, function (err) {
+        server3.pack.register({ plugin: require('../'), options: null }, function (err) {
 
             expect(err).to.not.exist;
 
@@ -241,7 +254,7 @@
             }
         ]);
 
-        server3.pack.require('../', { autoGenerate: false }, function (err) {
+        server3.pack.register({ plugin: require('../'), options: { autoGenerate: false } }, function (err) {
 
             expect(err).to.not.exist;
 
@@ -258,4 +271,31 @@
             });
         });
     });
+
+    it('does not set crumb cookie insecurely', function(done) {
+        var options = {
+            cors: true
+        }
+        var server4 = new Hapi.Server(options);
+        server4.route([
+            {
+                method: 'GET', path: '/1', handler: function (request, reply) {
+
+                    return reply('test');
+                }
+            }
+        ]);
+        server4.pack.register({ plugin: require('../'), options: null }, function (err) {
+            expect(err).to.not.exist;
+            var headers = {};
+            headers['Origin'] = '127.0.0.1'
+            server4.inject({ method: 'GET', url: '/1', headers: headers }, function (res) {
+
+                var header = res.headers['set-cookie'];
+                expect(header).to.not.contain('crumb');
+
+                done();
+            });
+        });
+    });
 });
```
