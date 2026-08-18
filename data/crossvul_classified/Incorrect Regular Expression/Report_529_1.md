# CrossVul Fix Pair: Incorrect Regular Expression in json
**Pair ID:** 529_1
**Vulnerability Class:** Incorrect Regular Expression
**CWE:** CWE-185
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `529_1`)

## Vulnerability Information & PoC

## Description
Incorrect Regular Expression - When the regular expression is used in protection mechanisms such as filtering or validation, this may allow an attacker to bypass the intended restrictions on the incoming data.

## Vulnerable Code
```json
Lines 65-87 of the vulnerable file.

    "pngjs": "^3.3.0",
    "qunitjs": "^2.4.0",
    "request": "^2.81.0",
    "requirejs": "^2.3.3",
    "vinyl-ftp": "^0.4.5",
    "webpack": "^1.15.0",
    "xml2js": "^0.4.17",
    "yargs": "^3.32.0"
  },
  "lint-staged": {
    "*.js": [
      "eslint",
      "git add"
    ]
  },
  "license": "SEE LICENSE IN <license.txt>",
  "dependencies": {
    "aws-sdk": "^2.94.0",
    "babel-runtime": "^6.20.0",
    "glob": "^7.1.2",
    "taffydb": "^2.7.3"
  }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -82,6 +82,7 @@
     "aws-sdk": "^2.94.0",
     "babel-runtime": "^6.20.0",
     "glob": "^7.1.2",
+    "safe-regex": "^1.1.0",
     "taffydb": "^2.7.3"
   }
 }
```
