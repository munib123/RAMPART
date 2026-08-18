# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in json
**Pair ID:** 4610_1
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4610_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```json
Lines 1-22 of the vulnerable file.

{
  "name": "pixl-class",
  "version": "1.0.2",
  "description": "A simple module for creating classes, with inheritance and mixins.",
  "author": "Joseph Huckaby <jhuckaby@gmail.com>",
  "homepage": "https://github.com/jhuckaby/pixl-class",
  "license": "MIT",
  "main": "class.js",
  "repository": {
    "type": "git",
    "url": "https://github.com/jhuckaby/pixl-class"
  },
  "bugs": {
    "url": "https://github.com/jhuckaby/pixl-class/issues"
  },
  "keywords": [
    "oop",
    "class"
  ],
  "dependencies": {},
  "devDependencies": {}
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,22 +1,22 @@
 {
-  "name": "pixl-class",
-  "version": "1.0.2",
-  "description": "A simple module for creating classes, with inheritance and mixins.",
-  "author": "Joseph Huckaby <jhuckaby@gmail.com>",
-  "homepage": "https://github.com/jhuckaby/pixl-class",
-  "license": "MIT",
-  "main": "class.js",
-  "repository": {
-    "type": "git",
-    "url": "https://github.com/jhuckaby/pixl-class"
-  },
-  "bugs": {
-    "url": "https://github.com/jhuckaby/pixl-class/issues"
-  },
-  "keywords": [
-    "oop",
-    "class"
-  ],
-  "dependencies": {},
-  "devDependencies": {}
+	"name": "pixl-class",
+	"version": "1.0.3",
+	"description": "A simple module for creating classes, with inheritance and mixins.",
+	"author": "Joseph Huckaby <jhuckaby@gmail.com>",
+	"homepage": "https://github.com/jhuckaby/pixl-class",
+	"license": "MIT",
+	"main": "class.js",
+	"repository": {
+		"type": "git",
+		"url": "https://github.com/jhuckaby/pixl-class"
+	},
+	"bugs": {
+		"url": "https://github.com/jhuckaby/pixl-class/issues"
+	},
+	"keywords": [
+		"oop",
+		"class"
+	],
+	"dependencies": {},
+	"devDependencies": {}
 }
```
