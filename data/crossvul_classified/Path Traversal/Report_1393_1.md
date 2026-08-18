# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in json
**Pair ID:** 1393_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1393_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```json
Lines 77-111 of the vulnerable file.

    "grunt-exec": "^0.4.7",
    "grunt-simple-mocha": "^0.4.1",
    "husky": "^0.14.3",
    "in-publish": "^2.0.0",
    "istanbul": "^0.4.3",
    "lint-staged": "^7.0.0",
    "load-grunt-tasks": "^3.5.0",
    "mocha": "^2.5.3",
    "multiline": "^1.0.2",
    "nock": "^9.2.3",
    "node-uuid": "^1.4.7",
    "prettier": "^1.11.1",
    "proxyquire": "^1.7.9",
    "spawn-sync": "1.0.15",
    "wrench": "^1.5.8"
  },
  "scripts": {
    "test": "grunt test",
    "ci": "grunt travis",
    "coveralls": "coveralls",
    "prepublish": "in-publish && echo 'You need to use \"grunt publish\" to publish bower' && false || not-in-publish",
    "format": "prettier --write --single-quote --tab-width 4 '**/*.js'",
    "precommit": "lint-staged"
  },
  "lint-staged": {
    "*.js": [
      "prettier --single-quote --tab-width 4",
      "git add"
    ]
  },
  "files": [
    "bin",
    "lib"
  ]
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -94,7 +94,7 @@
     "test": "grunt test",
     "ci": "grunt travis",
     "coveralls": "coveralls",
-    "prepublish": "in-publish && echo 'You need to use \"grunt publish\" to publish bower' && false || not-in-publish",
+    "prepublishOnly": "in-publish && echo 'You need to use \"grunt publish\" to publish bower' && false || not-in-publish",
     "format": "prettier --write --single-quote --tab-width 4 '**/*.js'",
     "precommit": "lint-staged"
   },
```
