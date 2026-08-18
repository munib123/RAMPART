# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in json
**Pair ID:** 954_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `954_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```json
Lines 30-70 of the vulnerable file.

    "test:types": "tsc -p test/types",
    "test:unit": "jest test/unit packages --forceExit"
  },
  "devDependencies": {
    "@babel/core": "^7.4.3",
    "@babel/preset-env": "^7.4.3",
    "@nuxtjs/eslint-config": "^0.0.1",
    "@vue/server-test-utils": "^1.0.0-beta.29",
    "@vue/test-utils": "^1.0.0-beta.29",
    "babel-eslint": "^10.0.1",
    "babel-jest": "^24.7.1",
    "babel-plugin-dynamic-import-node": "^2.2.0",
    "cheerio": "^1.0.0-rc.3",
    "codecov": "^3.3.0",
    "consola": "^2.6.0",
    "cross-env": "^5.2.0",
    "cross-spawn": "^6.0.5",
    "eslint": "^5.16.0",
    "eslint-config-standard": "^12.0.0",
    "eslint-multiplexer": "^1.0.4",
    "eslint-plugin-import": "^2.17.0",
    "eslint-plugin-jest": "^22.4.1",
    "eslint-plugin-node": "^8.0.1",
    "eslint-plugin-promise": "^4.1.1",
    "eslint-plugin-standard": "^4.0.0",
    "eslint-plugin-vue": "^5.2.2",
    "esm": "3.2.20",
    "execa": "^1.0.0",
    "express": "^4.16.4",
    "finalhandler": "^1.1.1",
    "fork-ts-checker-webpack-plugin": "^1.0.2",
    "fs-extra": "^7.0.1",
    "get-port": "^5.0.0",
    "glob": "^7.1.3",
    "is-wsl": "^1.1.0",
    "jest": "^24.7.1",
    "jsdom": "^14.0.0",
    "klaw-sync": "^6.0.0",
    "lerna": "^3.13.2",
    "lodash": "^4.17.11",
    "node-fetch": "^2.3.0",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -47,7 +47,7 @@
     "eslint": "^5.16.0",
     "eslint-config-standard": "^12.0.0",
     "eslint-multiplexer": "^1.0.4",
-    "eslint-plugin-import": "^2.17.0",
+    "eslint-plugin-import": "^2.17.1",
     "eslint-plugin-jest": "^22.4.1",
     "eslint-plugin-node": "^8.0.1",
     "eslint-plugin-promise": "^4.1.1",
```
