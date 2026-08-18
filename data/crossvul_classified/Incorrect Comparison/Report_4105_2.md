# CrossVul Fix Pair: Incorrect Comparison in json
**Pair ID:** 4105_2
**Vulnerability Class:** Incorrect Comparison
**CWE:** CWE-697
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4105_2`)

## Vulnerability Information & PoC

## Description
Incorrect Comparison - This Pillar covers several possibilities: the comparison checks one factor incorrectly; the comparison should consider multiple factors, but it does not check at least one of those factors at all; ...

## Vulnerable Code
```json
Lines 27-67 of the vulnerable file.

    "simpleledger"
  ],
  "author": "James Cramer",
  "license": "ISC",
  "unpkg": "dist/slpjs.min.js",
  "bugs": {
    "url": "https://github.com/simpleledger/slpjs/issues"
  },
  "homepage": "https://github.com/simpleledger/slpjs#readme",
  "devDependencies": {
    "@istanbuljs/nyc-config-typescript": "^0.1.3",
    "@types/mocha": "^7.0.2",
    "@types/node": "^10.17.26",
    "bitbox-sdk": "^8.11.2",
    "bitcoin-rpc-promise": "^2.1.6",
    "bitcore-lib-cash": "^9.0.0",
    "browserify": "^16.5.1",
    "mkdirp": "^0.5.5",
    "mocha": "^7.2.0",
    "nyc": "^15.1.0",
    "slp-unit-test-data": "git+https://github.com/simpleledger/slp-unit-test-data.git#a450146e112aee4db5a1b33dc978229fdcfb23a4",
    "source-map-support": "^0.5.19",
    "ts-node": "^7.0.1",
    "typescript": "^3.9.5",
    "typescript-tslint-plugin": "^0.5.5",
    "uglify-es": "^3.3.9"
  },
  "peerDependencies": {
    "bitbox-sdk": "^8.11.2",
    "bitcore-lib-cash": "^9.0.0"
  },
  "dependencies": {
    "@types/crypto-js": "^3.1.47",
    "@types/lodash": "^4.14.156",
    "@types/randombytes": "^2.0.0",
    "@types/socket.io": "^2.1.8",
    "@types/socket.io-client": "^1.4.33",
    "@types/wif": "^2.0.1",
    "axios": "^0.18.1",
    "bchaddrjs-slp": "0.2.8",
    "bignumber.js": "9.0.0",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -44,7 +44,7 @@
     "mkdirp": "^0.5.5",
     "mocha": "^7.2.0",
     "nyc": "^15.1.0",
-    "slp-unit-test-data": "git+https://github.com/simpleledger/slp-unit-test-data.git#a450146e112aee4db5a1b33dc978229fdcfb23a4",
+    "slp-unit-test-data": "git+https://github.com/simpleledger/slp-unit-test-data.git#8c942eacfae12686dcf1f3366321445a4fba73e7",
     "source-map-support": "^0.5.19",
     "ts-node": "^7.0.1",
     "typescript": "^3.9.5",
```
