# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in json
**Pair ID:** 4499_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4499_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```json
Lines 16-37 of the vulnerable file.

  ],
  "scripts": {
    "build": "rimraf dist && tsc",
    "prepare": "npm run build"
  },
  "keywords": [
    "graphql",
    "graphiql",
    "playground",
    "graphcool"
  ],
  "devDependencies": {
    "@types/node": "12.12.34",
    "rimraf": "3.0.2",
    "typescript": "3.8.3"
  },
  "typings": "dist/index.d.ts",
  "typescript": {
    "definition": "dist/index.d.ts"
  },
  "dependencies": {}
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,5 +33,7 @@
   "typescript": {
     "definition": "dist/index.d.ts"
   },
-  "dependencies": {}
+  "dependencies": {
+    "xss": "^1.0.6"
+  }
 }
```
