# CrossVul Fix Pair: Resource Management Errors in javascript
**Pair ID:** 4955_4
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4955_4`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```javascript
Lines 78-118 of the vulnerable file.


        it('parses IPv6 headers', (done) => {

            const req = {
                method: 'POST',
                url: '/resource/4?filter=a',
                headers: {
                    host: '[123:123:123]:8000',
                    'content-type': 'text/plain;x=y'
                },
                connection: {
                    encrypted: true
                }
            };

            const host = Hawk.utils.parseHost(req, 'Host');
            expect(host.port).to.equal('8000');
            expect(host.name).to.equal('[123:123:123]');
            done();
        });
    });

    describe('version()', () => {

        it('returns the correct package version number', (done) => {

            expect(Hawk.utils.version()).to.equal(Package.version);
            done();
        });
    });

    describe('unauthorized()', () => {

        it('returns a hawk 401', (done) => {

            expect(Hawk.utils.unauthorized('kaboom').output.headers['WWW-Authenticate']).to.equal('Hawk error="kaboom"');
            done();
        });

        it('supports attributes', (done) => {

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -95,6 +95,34 @@
             expect(host.name).to.equal('[123:123:123]');
             done();
         });
+
+        it('errors on header too long', (done) => {
+
+            let long = '';
+            for (let i = 0; i < 5000; ++i) {
+                long += 'x';
+            }
+
+            expect(Hawk.utils.parseHost({ headers: { host: long } })).to.be.null();
+            done();
+        });
+    });
+
+    describe('parseAuthorizationHeader()', () => {
+
+        it('errors on header too long', (done) => {
+
+            let long = 'Scheme a="';
+            for (let i = 0; i < 5000; ++i) {
+                long += 'x';
+            }
+            long += '"';
+
+            const err = Hawk.utils.parseAuthorizationHeader(long, ['a']);
+            expect(err).to.be.instanceof(Error);
+            expect(err.message).to.equal('Header length too long');
+            done();
+        });
     });
 
     describe('version()', () => {
```
