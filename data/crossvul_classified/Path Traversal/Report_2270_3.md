# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in javascript
**Pair ID:** 2270_3
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2270_3`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```javascript
Lines 1080-1120 of the vulnerable file.


      request(server)
      .get('/')
      .expect(200, /tobi/, done)
    })
  })

  describe('root', function(){
    describe('when given', function(){
      it('should join root', function(done){
        var app = http.createServer(function(req, res){
          send(req, req.url, {root: __dirname + '/fixtures'})
          .pipe(res);
        });

        request(app)
        .get('/pets/../name.txt')
        .expect(200, 'tobi', done)
      })

      it('should restrict paths to within root', function(done){
        var app = http.createServer(function(req, res){
          send(req, req.url, {root: __dirname + '/fixtures'})
          .pipe(res);
        });

        request(app)
        .get('/pets/../../send.js')
        .expect(403, done)
      })

      it('should allow .. in root', function(done){
        var app = http.createServer(function(req, res){
          send(req, req.url, {root: __dirname + '/fixtures/../fixtures'})
          .pipe(res);
        });

        request(app)
        .get('/pets/../../send.js')
        .expect(403, done)
      })
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1097,6 +1097,17 @@
         .expect(200, 'tobi', done)
       })
 
+      it('should with with trailing slash', function(done){
+        var app = http.createServer(function(req, res){
+          send(req, req.url, {root: __dirname + '/fixtures/'})
+          .pipe(res);
+        });
+
+        request(app)
+        .get('/name.txt')
+        .expect(200, 'tobi', done)
+      })
+
       it('should restrict paths to within root', function(done){
         var app = http.createServer(function(req, res){
           send(req, req.url, {root: __dirname + '/fixtures'})
@@ -1116,6 +1127,17 @@
 
         request(app)
         .get('/pets/../../send.js')
+        .expect(403, done)
+      })
+
+      it('should not allow root transversal', function(done){
+        var app = http.createServer(function(req, res){
+          send(req, req.url, {root: __dirname + '/fixtures/name.d'})
+          .pipe(res);
+        });
+
+        request(app)
+        .get('/../name.dir/name.txt')
         .expect(403, done)
       })
     })
```
