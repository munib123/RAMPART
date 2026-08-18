# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in json
**Pair ID:** 2006_1
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2006_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```json
Lines 16-48 of the vulnerable file.

    "git log",
    "source control"
  ],
  "author": "omrilotan",
  "license": "MIT",
  "repository": {
    "type": "git",
    "url": "git+https://github.com/omrilotan/async-git.git"
  },
  "homepage": "https://omrilotan.com/async-git/",
  "main": "index.js",
  "scripts": {
    "test": "mocha '**/spec.js' --require .mocha.js --recursive --exclude 'node_modules'",
    "lint": "eslint . --ext .js"
  },
  "dependencies": {
    "@does/exist": "^1.1.0",
    "async-execute": "^1.1.0"
  },
  "devDependencies": {
    "@omrilotan/eslint-config": "^1.1.0",
    "abuser": "^2.0.2",
    "chai": "^4.2.0",
    "chai-as-promised": "^7.1.1",
    "deep-equal-in-any-order": "^1.0.21",
    "eslint": "^7.0.0",
    "eslint-plugin-log": "^1.2.3",
    "index-require": "^1.0.1",
    "mocha": "^8.0.1",
    "sinon": "^9.0.1",
    "sinon-chai": "^3.3.0"
  }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,6 +33,7 @@
     "async-execute": "^1.1.0"
   },
   "devDependencies": {
+    "@lets/wait": "^2.0.2",
     "@omrilotan/eslint-config": "^1.1.0",
     "abuser": "^2.0.2",
     "chai": "^4.2.0",
```
