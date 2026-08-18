# CrossVul Fix Pair: Resource Management Errors in javascript
**Pair ID:** 4955_3
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4955_3`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```javascript
Lines 954-994 of the vulnerable file.


            const artifacts = {
                method: 'POST',
                host: 'example.com',
                port: '8080',
                resource: '/resource/4?filter=a',
                ts: '1398546787',
                nonce: 'xUwusx',
                hash: 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                ext: 'some-app-data',
                mac: 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
                id: '123456'
            };

            const header = Hawk.server.header(credentials, artifacts, { payload: 'some reply', contentType: 'text/plain', ext: 'response-specific' });
            expect(header).to.equal('');
            done();
        });
    });

    describe('authenticateMessage()', () => {

        it('errors on invalid authorization (ts)', (done) => {

            credentialsFunc('123456', (err, credentials1) => {

                expect(err).to.not.exist();

                const auth = Hawk.client.message('example.com', 8080, 'some message', { credentials: credentials1 });
                delete auth.ts;

                Hawk.server.authenticateMessage('example.com', 8080, 'some message', auth, credentialsFunc, {}, (err, credentials2) => {

                    expect(err).to.exist();
                    expect(err.message).to.equal('Invalid authorization');
                    done();
                });
            });
        });

        it('errors on invalid authorization (nonce)', (done) => {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -971,6 +971,33 @@
         });
     });
 
+    describe('authenticateBewit()', () => {
+
+        it('errors on uri too long', (done) => {
+
+            let long = '/';
+            for (let i = 0; i < 5000; ++i) {
+                long += 'x';
+            }
+
+            const req = {
+                method: 'GET',
+                url: long,
+                host: 'example.com',
+                port: 8080,
+                authorization: 'Hawk id="1", ts="1353788437", nonce="k3j4h2", mac="zy79QQ5/EYFmQqutVnYb73gAc/U=", ext="hello"'
+            };
+
+            Hawk.server.authenticateBewit(req, credentialsFunc, {}, (err, credentials, bewit) => {
+
+                expect(err).to.exist();
+                expect(err.output.statusCode).to.equal(400);
+                expect(err.message).to.equal('Resource path exceeds max length');
+                done();
+            });
+        });
+    });
+
     describe('authenticateMessage()', () => {
 
         it('errors on invalid authorization (ts)', (done) => {
```
