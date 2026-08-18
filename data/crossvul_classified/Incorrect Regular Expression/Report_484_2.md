# CrossVul Fix Pair: Incorrect Regular Expression in json
**Pair ID:** 484_2
**Vulnerability Class:** Incorrect Regular Expression
**CWE:** CWE-185
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `484_2`)

## Vulnerability Information & PoC

## Description
Incorrect Regular Expression - When the regular expression is used in protection mechanisms such as filtering or validation, this may allow an attacker to bypass the intended restrictions on the incoming data.

## Vulnerable Code
```json
Lines 8-35 of the vulnerable file.

      "email": "tobie.langel@gmail.com",
      "web": "http://tobielangel.com"
    },
    {
      "name": "Lindsey Simon",
      "email": "lsimon@commoner.com",
      "web": "http://www.idreamofuni.com"
    }
  ],
  "repository": {
    "type": "git",
    "url": "http://github.com/ua-parser/uap-core.git"
  },
  "licenses": [
    {
      "type": "Apache-2.0",
      "url": "https://raw.github.com/ua-parser/uap-core/master/LICENSE"
    }
  ],
  "devDependencies": {
    "yamlparser": ">=0.0.2",
    "mocha": "*",
    "uap-ref-impl": "ua-parser/uap-ref-impl"
  },
  "scripts": {
    "test": "mocha -u tdd -R min ./tests/test.js"
  }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,11 +25,12 @@
     }
   ],
   "devDependencies": {
-    "yamlparser": ">=0.0.2",
     "mocha": "*",
-    "uap-ref-impl": "ua-parser/uap-ref-impl"
+    "safe-regex": "^2.0.1",
+    "uap-ref-impl": "git+https://github.com/ua-parser/uap-ref-impl#master",
+    "yamlparser": ">=0.0.2"
   },
   "scripts": {
-    "test": "mocha -u tdd -R min ./tests/test.js"
+    "test": "mocha --opts ./tests/mocha.opts ./tests"
   }
 }
```
