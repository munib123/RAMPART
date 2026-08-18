# CrossVul Fix Pair: Deserialization of Untrusted Data in json
**Pair ID:** 4613_1
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4613_1`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```json
Lines 1575-1615 of the vulnerable file.

          "integrity": "sha512-ak9Qy5Q7jYb2Wwcey5Fpvg2KoAc/ZIhLSLOSBmRmygPsGwkVVt0fZa0qrtMz+m6tJTAHfZQ8FnmB4MG4LWy7/w==",
          "dev": true
        }
      }
    },
    "platform": {
      "version": "1.3.5",
      "resolved": "https://registry.npmjs.org/platform/-/platform-1.3.5.tgz",
      "integrity": "sha512-TuvHS8AOIZNAlE77WUDiR4rySV/VMptyMfcfeoMgs4P8apaZM3JrnbzBiixKUv+XR6i+BXrQh8WAnjaSPFO65Q==",
      "dev": true
    },
    "process-on-spawn": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/process-on-spawn/-/process-on-spawn-1.0.0.tgz",
      "integrity": "sha512-1WsPDsUSMmZH5LeMLegqkPDrsGgsWwk1Exipy2hvB0o/F0ASzbpIctSCcZIK1ykJvtTJULEH+20WOFjMvGnCTg==",
      "dev": true,
      "requires": {
        "fromentries": "^1.2.0"
      }
    },
    "readdirp": {
      "version": "3.2.0",
      "resolved": "https://registry.npmjs.org/readdirp/-/readdirp-3.2.0.tgz",
      "integrity": "sha512-crk4Qu3pmXwgxdSgGhgA/eXiJAPQiX4GMOZZMXnqKxHX7TaoL+3gQVo/WeuAiogr07DpnfjIMpXXa+PAIvwPGQ==",
      "dev": true,
      "requires": {
        "picomatch": "^2.0.4"
      }
    },
    "release-zalgo": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/release-zalgo/-/release-zalgo-1.0.0.tgz",
      "integrity": "sha1-CXALflB0Mpc5Mw5TXFqQ+2eFFzA=",
      "dev": true,
      "requires": {
        "es6-error": "^4.0.1"
      }
    },
    "require-directory": {
      "version": "2.1.1",
      "resolved": "https://registry.npmjs.org/require-directory/-/require-directory-2.1.1.tgz",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1592,6 +1592,14 @@
         "fromentries": "^1.2.0"
       }
     },
+    "randombytes": {
+      "version": "2.1.0",
+      "resolved": "https://registry.npmjs.org/randombytes/-/randombytes-2.1.0.tgz",
+      "integrity": "sha512-vYl3iOX+4CKUWuxGi9Ukhie6fsqXqS9FE2Zaic4tNFD2N2QQaXOMFbuKK4QmDHC0JO6B1Zp41J0LpT0oR68amQ==",
+      "requires": {
+        "safe-buffer": "^5.1.0"
+      }
+    },
     "readdirp": {
       "version": "3.2.0",
       "resolved": "https://registry.npmjs.org/readdirp/-/readdirp-3.2.0.tgz",
@@ -1649,8 +1657,7 @@
     "safe-buffer": {
       "version": "5.1.2",
       "resolved": "https://registry.npmjs.org/safe-buffer/-/safe-buffer-5.1.2.tgz",
-      "integrity": "sha512-Gd2UZBJDkXlY7GbJxfsE8/nvKkUEU1G38c1siN6QP6a9PT9MmHB8GnpscSmMJSoF8LOIrt8ud/wPtojys4G6+g==",
-      "dev": true
+      "integrity": "sha512-Gd2UZBJDkXlY7GbJxfsE8/nvKkUEU1G38c1siN6QP6a9PT9MmHB8GnpscSmMJSoF8LOIrt8ud/wPtojys4G6+g=="
     },
     "semver": {
       "version": "5.7.1",
```
