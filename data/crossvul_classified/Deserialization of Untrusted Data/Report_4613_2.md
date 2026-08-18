# CrossVul Fix Pair: Deserialization of Untrusted Data in json
**Pair ID:** 4613_2
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4613_2`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```json
Lines 12-33 of the vulnerable file.

    "url": "git+https://github.com/yahoo/serialize-javascript.git"
  },
  "keywords": [
    "serialize",
    "serialization",
    "javascript",
    "js",
    "json"
  ],
  "author": "Eric Ferraiuolo <edf@ericf.me>",
  "license": "BSD-3-Clause",
  "bugs": {
    "url": "https://github.com/yahoo/serialize-javascript/issues"
  },
  "homepage": "https://github.com/yahoo/serialize-javascript",
  "devDependencies": {
    "benchmark": "^2.1.4",
    "chai": "^4.1.0",
    "mocha": "^7.0.0",
    "nyc": "^15.0.0"
  }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,5 +29,8 @@
     "chai": "^4.1.0",
     "mocha": "^7.0.0",
     "nyc": "^15.0.0"
+  },
+  "dependencies": {
+    "randombytes": "^2.1.0"
   }
 }
```
