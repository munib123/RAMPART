# CrossVul Fix Pair: Improper Input Validation in json
**Pair ID:** 1950_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1950_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```json
Lines 16-56 of the vulnerable file.

  "keywords": [
    "fastify",
    "http",
    "proxy"
  ],
  "author": "Matteo Collina <hello@matteocollina.com>",
  "license": "MIT",
  "bugs": {
    "url": "https://github.com/fastify/fastify-http-proxy/issues"
  },
  "homepage": "https://github.com/fastify/fastify-http-proxy#readme",
  "devDependencies": {
    "@types/node": "^14.0.27",
    "@types/ws": "^7.4.0",
    "@typescript-eslint/parser": "^4.0.0",
    "eslint-plugin-typescript": "^0.14.0",
    "express": "^4.16.4",
    "express-http-proxy": "^1.6.2",
    "fast-proxy": "^1.7.0",
    "fastify": "^3.0.0",
    "got": "^11.5.1",
    "http-errors": "^1.8.0",
    "http-proxy": "^1.17.0",
    "make-promises-safe": "^5.0.0",
    "simple-get": "^4.0.0",
    "snazzy": "^9.0.0",
    "socket.io": "^3.0.4",
    "socket.io-client": "^3.0.4",
    "standard": "^16.0.3",
    "tap": "^14.10.8",
    "tsd": "^0.14.0",
    "typescript": "^4.0.2"
  },
  "dependencies": {
    "fastify-reply-from": "^4.0.0",
    "ws": "^7.4.1"
  },
  "tsd": {
    "directory": "test"
  }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,6 +33,7 @@
     "express-http-proxy": "^1.6.2",
     "fast-proxy": "^1.7.0",
     "fastify": "^3.0.0",
+    "fastify-websocket": "^3.0.0",
     "got": "^11.5.1",
     "http-errors": "^1.8.0",
     "http-proxy": "^1.17.0",
```
