# CrossVul Fix Pair: Incorrect Comparison in json
**Pair ID:** 4106_1
**Vulnerability Class:** Incorrect Comparison
**CWE:** CWE-697
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4106_1`)

## Vulnerability Information & PoC

## Description
Incorrect Comparison - This Pillar covers several possibilities: the comparison checks one factor incorrectly; the comparison should consider multiple factors, but it does not check at least one of those factors at all; ...

## Vulnerable Code
```json
Lines 4070-4110 of the vulnerable file.

    },
    "shell-quote": {
      "version": "1.7.2",
      "resolved": "https://registry.npmjs.org/shell-quote/-/shell-quote-1.7.2.tgz",
      "integrity": "sha512-mRz/m/JVscCrkMyPqHc/bczi3OQHkLTqXHEFu0zDhK/qfv3UcOA4SVmRCLmos4bhjr9ekVQubj/R7waKapmiQg==",
      "dev": true
    },
    "signal-exit": {
      "version": "3.0.3",
      "resolved": "https://registry.npmjs.org/signal-exit/-/signal-exit-3.0.3.tgz",
      "integrity": "sha512-VUJ49FC8U1OxwZLxIbTTrDvLnf/6TDgxZcK8wxR8zs13xpx7xbG60ndBlhNrFi2EMuFRoeDoJO7wthSLq42EjA==",
      "dev": true
    },
    "simple-concat": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/simple-concat/-/simple-concat-1.0.0.tgz",
      "integrity": "sha1-c0TLuLbib7J9ZrL8hvn21Zl1IcY=",
      "dev": true
    },
    "slp-unit-test-data": {
      "version": "git+https://github.com/simpleledger/slp-unit-test-data.git#be74a6005dbf7dfabce19a9f920b2632b539f73e",
      "from": "git+https://github.com/simpleledger/slp-unit-test-data.git",
      "dev": true
    },
    "source-map": {
      "version": "0.5.7",
      "resolved": "https://registry.npmjs.org/source-map/-/source-map-0.5.7.tgz",
      "integrity": "sha1-igOdLRAh0i0eoUyA2OpGi6LvP8w=",
      "dev": true
    },
    "source-map-support": {
      "version": "0.5.16",
      "resolved": "https://registry.npmjs.org/source-map-support/-/source-map-support-0.5.16.tgz",
      "integrity": "sha512-efyLRJDr68D9hBBNIPWFjhpFzURh+KJykQwvMyW5UiZzYwoF6l4YMMDIJJEyFWxWCqfyxLzz6tSfUFR+kXXsVQ==",
      "dev": true,
      "requires": {
        "buffer-from": "^1.0.0",
        "source-map": "^0.6.0"
      },
      "dependencies": {
        "source-map": {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4087,7 +4087,7 @@
       "dev": true
     },
     "slp-unit-test-data": {
-      "version": "git+https://github.com/simpleledger/slp-unit-test-data.git#be74a6005dbf7dfabce19a9f920b2632b539f73e",
+      "version": "git+https://github.com/simpleledger/slp-unit-test-data.git#8c942eacfae12686dcf1f3366321445a4fba73e7",
       "from": "git+https://github.com/simpleledger/slp-unit-test-data.git",
       "dev": true
     },
```
