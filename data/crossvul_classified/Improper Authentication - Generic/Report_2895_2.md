# CrossVul Fix Pair: Improper Authentication in javascript
**Pair ID:** 2895_2
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2895_2`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```javascript
Lines 370-410 of the vulnerable file.

                server.start((err) => {

                    expect(err).to.not.exist();
                    server.inject({ url: '/nes/auth', headers: { authorization: 'Custom john' } }, (res) => {

                        expect(res.result.status).to.equal('authenticated');

                        const header = res.headers['set-cookie'][0];
                        const cookie = header.match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

                        const client = new Nes.Client('http://localhost:' + server.info.port, { ws: { headers: { cookie: 'nes=' + cookie[1] } } });
                        client.connect({ auth: 'something' }, (err) => {

                            expect(err).to.exist();
                            expect(err.message).to.equal('Connection already authenticated');
                            expect(err.statusCode).to.equal(400);

                            client.disconnect();
                            server.stop(done);
                        });
                    });
                });
            });
        });

        it('overrides cookie path', (done) => {

            const server = new Hapi.Server();
            server.connection();

            server.auth.scheme('custom', internals.implementation);
            server.auth.strategy('default', 'custom', true);

            server.register({ register: Nes, options: { auth: { type: 'cookie', password, path: '/nes/xyz' } } }, (err) => {

                expect(err).to.not.exist();

                server.route({
                    method: 'GET',
                    path: '/',
                    handler: function (request, reply) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -387,6 +387,41 @@
                             client.disconnect();
                             server.stop(done);
                         });
+                    });
+                });
+            });
+        });
+
+        it('errors on invalid cookie', (done) => {
+
+            const server = new Hapi.Server();
+            server.connection();
+
+            server.register({ register: Nes, options: { auth: { type: 'cookie' } } }, (err) => {
+
+                expect(err).to.not.exist();
+
+                server.auth.scheme('custom', internals.implementation);
+                server.auth.strategy('default', 'custom', true);
+
+                server.route({
+                    method: 'GET',
+                    path: '/',
+                    handler: function (request, reply) {
+
+                        return reply('hello');
+                    }
+                });
+
+                server.start((err) => {
+
+                    expect(err).to.not.exist();
+                    const client = new Nes.Client('http://localhost:' + server.info.port, { ws: { headers: { cookie: '"' } } });
+                    client.connect((err) => {
+
+                        expect(err).to.be.an.error('Invalid nes authentication cookie');
+                        client.disconnect();
+                        server.stop(done);
                     });
                 });
             });
```
