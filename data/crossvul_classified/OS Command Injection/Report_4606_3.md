# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in json
**Pair ID:** 4606_3
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4606_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```json
Lines 18-59 of the vulnerable file.

    "codecov.io",
    "codecov"
  ],
  "bin": {
    "codecov": "./bin/codecov"
  },
  "engines": {
    "node": ">=4.0"
  },
  "author": "Codecov <hello@codecov.io>",
  "license": "MIT",
  "bugs": {
    "url": "https://github.com/codecov/codecov-node/issues"
  },
  "homepage": "https://github.com/codecov/codecov-node",
  "dependencies": {
    "argv": "0.0.2",
    "ignore-walk": "3.0.3",
    "js-yaml": "3.13.1",
    "teeny-request": "6.0.1",
    "urlgrey": "0.4.4",
    "validator": "12.2.0"
  },
  "devDependencies": {
    "eslint": "^5.16.0",
    "eslint-config-prettier": "^4.1.0",
    "husky": "4.2.1",
    "jest": "^24.8.0",
    "lint-staged": "10.0.7",
    "mock-fs": "4.10.4",
    "prettier": "1.19.1"
  },
  "husky": {
    "hooks": {
      "pre-commit": "npm run lint && lint-staged",
      "pre-push": "npm test"
    }
  },
  "lint-staged": {
    "*.{ts,js,json,md}": [
      "prettier --write",
      "git add"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -35,8 +35,7 @@
     "ignore-walk": "3.0.3",
     "js-yaml": "3.13.1",
     "teeny-request": "6.0.1",
-    "urlgrey": "0.4.4",
-    "validator": "12.2.0"
+    "urlgrey": "0.4.4"
   },
   "devDependencies": {
     "eslint": "^5.16.0",
```
