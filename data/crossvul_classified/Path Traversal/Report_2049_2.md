# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in javascript
**Pair ID:** 2049_2
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2049_2`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```javascript
Lines 257-297 of the vulnerable file.


            expect(res.statusCode).to.equal(200);
            expect(res.payload).to.contain('package.json');
            done();
        });
    });

    it('returns the index when found', function (done) {

        var server = provisionServer({ files: { relativeTo: __dirname } });
        server.route({ method: 'GET', path: '/directoryIndex/{path*}', handler: { directoryTest: { path: './directory/' } } });

        server.inject('/directoryIndex/', function (res) {

            expect(res.statusCode).to.equal(200);
            expect(res.payload).to.contain('<p>test</p>');
            done();
        });
    });

    it('returns the index when found in hidden folder', function (done) {

        var server = provisionServer({ files: { relativeTo: __dirname } });
        server.route({ method: 'GET', path: '/{path*}', handler: { directoryTest: { path: './directory/.dot' } } });

        server.inject('/index.html', function (res) {

            expect(res.statusCode).to.equal(200);
            expect(res.payload).to.contain('<p>test</p>');

            server.inject('/', function (res) {

                expect(res.statusCode).to.equal(200);
                expect(res.payload).to.contain('<p>test</p>');
                done();
            });
        });
    });

    it('returns listing when found in hidden folder', function (done) {

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -274,7 +274,7 @@
         });
     });
 
-    it('returns the index when found in hidden folder', function (done) {
+    it('returns the index when served from a hidden folder', function (done) {
 
         var server = provisionServer({ files: { relativeTo: __dirname } });
         server.route({ method: 'GET', path: '/{path*}', handler: { directoryTest: { path: './directory/.dot' } } });
@@ -293,7 +293,7 @@
         });
     });
 
-    it('returns listing when found in hidden folder', function (done) {
+    it('returns listing when served from a hidden folder', function (done) {
 
         var server = provisionServer({ files: { relativeTo: __dirname } });
         server.route({ method: 'GET', path: '/{path*}', handler: { directoryTest: { path: './directory/.dot', index: false, listing: true } } });
@@ -373,6 +373,35 @@
         });
     });
 
+    it('returns a 404 response when requesting a file in a hidden directory when showHidden is disabled', function (done) {
+
+        var server = provisionServer({ files: { relativeTo: __dirname } });
+        server.route({ method: 'GET', path: '/noshowhidden/{path*}', handler: { directoryTest: { path: './directory', listing: true } } });
+
+        server.inject('/noshowhidden/.dot/index.html', function (res) {
+
+            expect(res.statusCode).to.equal(404);
+
+            server.inject('/noshowhidden/.dot/', function (res) {
+
+                expect(res.statusCode).to.equal(404);
+                done();
+            });
+        });
+    });
+
+    it('returns a 404 response when requesting a hidden directory listing when showHidden is disabled', function (done) {
+
+        var server = provisionServer({ files: { relativeTo: __dirname } });
+        server.route({ method: 'GET', path: '/noshowhidden/{path*}', handler: { directoryTest: { path: './directory', listing: true, index: false } } });
+
+        server.inject('/noshowhidden/.dot/', function (res) {
+
+            expect(res.statusCode).to.equal(404);
+            done();
+        });
+    });
+
     it('returns a file when requesting a hidden file when showHidden is enabled', function (done) {
 
         var server = provisionServer({ files: { relativeTo: __dirname } });
@@ -382,6 +411,25 @@
 
             expect(res.payload).to.contain('Ssssh!\n');
             done();
+        });
+    });
+
+    it('returns a a file when requesting a file in a hidden directory when showHidden is enabled', function (done) {
+
+        var server = provisionServer({ files: { relativeTo: __dirname } });
+        server.route({ method: 'GET', path: '/noshowhidden/{path*}', handler: { directoryTest: { path: './directory', showHidden: true, listing: true } } });
+
+        server.inject('/noshowhidden/.dot/index.html', function (res) {
+
+            expect(res.statusCode).to.equal(200);
+            expect(res.payload).to.contain('test');
+
+            server.inject('/noshowhidden/.dot/', function (res) {
+
+                expect(res.statusCode).to.equal(200);
+                expect(res.payload).to.contain('test');
+                done();
+            });
         });
     });
 
```
