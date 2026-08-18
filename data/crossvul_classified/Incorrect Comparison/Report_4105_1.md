# CrossVul Fix Pair: Incorrect Comparison in json
**Pair ID:** 4105_1
**Vulnerability Class:** Incorrect Comparison
**CWE:** CWE-697
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4105_1`)

## Vulnerability Information & PoC

## Description
Incorrect Comparison - This Pillar covers several possibilities: the comparison checks one factor incorrectly; the comparison should consider multiple factors, but it does not check at least one of those factors at all; ...

## Vulnerable Code
```json
Lines 5575-5616 of the vulnerable file.

        "is-fullwidth-code-point": "^2.0.0"
      },
      "dependencies": {
        "is-fullwidth-code-point": {
          "version": "2.0.0",
          "resolved": "https://registry.npmjs.org/is-fullwidth-code-point/-/is-fullwidth-code-point-2.0.0.tgz",
          "integrity": "sha1-o7MKXE8ZkYMWeqq5O+764937ZU8=",
          "dev": true
        }
      }
    },
    "slp-mdm": {
      "version": "0.0.6",
      "resolved": "https://registry.npmjs.org/slp-mdm/-/slp-mdm-0.0.6.tgz",
      "integrity": "sha512-fbjlIg/o8OtzgK2JydC6POJp3Qup/rLgy4yB5hoLgxWRlERyJyE29ScwS3r9TTwPxe12qK55pyivAdNOZZXL0A==",
      "requires": {
        "bignumber.js": "^9.0.0"
      }
    },
    "slp-unit-test-data": {
      "version": "git+https://github.com/simpleledger/slp-unit-test-data.git#a450146e112aee4db5a1b33dc978229fdcfb23a4",
      "from": "git+https://github.com/simpleledger/slp-unit-test-data.git#a450146e112aee4db5a1b33dc978229fdcfb23a4",
      "dev": true
    },
    "socket.io": {
      "version": "2.3.0",
      "resolved": "https://registry.npmjs.org/socket.io/-/socket.io-2.3.0.tgz",
      "integrity": "sha512-2A892lrj0GcgR/9Qk81EaY2gYhCBxurV0PfmmESO6p27QPrUK1J3zdns+5QPqvUYK2q657nSj0guoIil9+7eFg==",
      "dev": true,
      "requires": {
        "debug": "~4.1.0",
        "engine.io": "~3.4.0",
        "has-binary2": "~1.0.2",
        "socket.io-adapter": "~1.1.0",
        "socket.io-client": "2.3.0",
        "socket.io-parser": "~3.4.0"
      }
    },
    "socket.io-adapter": {
      "version": "1.1.2",
      "resolved": "https://registry.npmjs.org/socket.io-adapter/-/socket.io-adapter-1.1.2.tgz",
      "integrity": "sha512-WzZRUj1kUjrTIrUKpZLEzFZ1OLj5FwLlAFQs9kuZJzJi5DKdU7FsWc36SNmA8iDOtwBQyT8FkrriRM8vXLYz8g==",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5592,8 +5592,8 @@
       }
     },
     "slp-unit-test-data": {
-      "version": "git+https://github.com/simpleledger/slp-unit-test-data.git#a450146e112aee4db5a1b33dc978229fdcfb23a4",
-      "from": "git+https://github.com/simpleledger/slp-unit-test-data.git#a450146e112aee4db5a1b33dc978229fdcfb23a4",
+      "version": "git+https://github.com/simpleledger/slp-unit-test-data.git#8c942eacfae12686dcf1f3366321445a4fba73e7",
+      "from": "git+https://github.com/simpleledger/slp-unit-test-data.git#8c942eacfae12686dcf1f3366321445a4fba73e7",
       "dev": true
     },
     "socket.io": {
```
