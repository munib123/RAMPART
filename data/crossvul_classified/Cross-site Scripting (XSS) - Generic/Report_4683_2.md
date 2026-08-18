# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in json
**Pair ID:** 4683_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4683_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```json
Lines 2650-2690 of the vulnerable file.

    "md5": {
      "version": "2.2.1",
      "resolved": "https://registry.npmjs.org/md5/-/md5-2.2.1.tgz",
      "integrity": "sha1-U6s41f48iJG6RlMp6iP6wFQBJvk=",
      "requires": {
        "charenc": "~0.0.1",
        "crypt": "~0.0.1",
        "is-buffer": "~1.1.1"
      }
    },
    "md5-file": {
      "version": "4.0.0",
      "resolved": "https://registry.npmjs.org/md5-file/-/md5-file-4.0.0.tgz",
      "integrity": "sha512-UC0qFwyAjn4YdPpKaDNw6gNxRf7Mcx7jC1UGCY4boCzgvU2Aoc1mOGzTtrjjLKhM5ivsnhoKpQVxKPp+1j1qwg=="
    },
    "mdurl": {
      "version": "1.0.1",
      "resolved": "https://registry.npmjs.org/mdurl/-/mdurl-1.0.1.tgz",
      "integrity": "sha1-/oWy7HWlkDfyrf7BAP1sYBdhFS4="
    },
    "micromatch": {
      "version": "3.1.10",
      "resolved": "https://registry.npmjs.org/micromatch/-/micromatch-3.1.10.tgz",
      "integrity": "sha512-MWikgl9n9M3w+bpsY3He8L+w9eF9338xRl8IAO5viDizwSzziFEyUzo2xrrloB64ADbTf8uA8vRqqttDTOmccg==",
      "requires": {
        "arr-diff": "^4.0.0",
        "array-unique": "^0.3.2",
        "braces": "^2.3.1",
        "define-property": "^2.0.2",
        "extend-shallow": "^3.0.2",
        "extglob": "^2.0.4",
        "fragment-cache": "^0.2.1",
        "kind-of": "^6.0.2",
        "nanomatch": "^1.2.9",
        "object.pick": "^1.3.0",
        "regex-not": "^1.0.0",
        "snapdragon": "^0.8.1",
        "to-regex": "^3.0.2"
      }
    },
    "mime": {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2667,6 +2667,11 @@
       "resolved": "https://registry.npmjs.org/mdurl/-/mdurl-1.0.1.tgz",
       "integrity": "sha1-/oWy7HWlkDfyrf7BAP1sYBdhFS4="
     },
+    "memory-cache": {
+      "version": "0.2.0",
+      "resolved": "https://registry.npmjs.org/memory-cache/-/memory-cache-0.2.0.tgz",
+      "integrity": "sha1-eJCwHVLADI68nVM+H46xfjA0hxo="
+    },
     "micromatch": {
       "version": "3.1.10",
       "resolved": "https://registry.npmjs.org/micromatch/-/micromatch-3.1.10.tgz",
@@ -2918,6 +2923,15 @@
       "requires": {
         "encoding": "^0.1.11",
         "is-stream": "^1.0.1"
+      }
+    },
+    "node-html-parser": {
+      "version": "1.2.4",
+      "resolved": "https://registry.npmjs.org/node-html-parser/-/node-html-parser-1.2.4.tgz",
+      "integrity": "sha512-qHwPdGyGr9pOZBoSgUOuNPG20QYZVN00lFcxKQgjPUODSxVH7obQeLVVawa3B4cfSNtLIeczSzoy/xYA8XG5WQ==",
+      "dev": true,
+      "requires": {
+        "he": "1.1.1"
       }
     },
     "node-persist": {
```
