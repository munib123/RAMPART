# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in json
**Pair ID:** 2538_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2538_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```json
Lines 1-28 of the vulnerable file.

{
  "compilerOptions": {
    "removeComments": true,
    "preserveConstEnums": true,
    "outDir": "../build/src/renderer",
    "noImplicitAny": true,
    "noImplicitReturns": true,
    "noUnusedLocals": false,
    "noUnusedParameters": true,
    "noEmitOnError": true,
    "target": "es5",
    "sourceMap": true
  },
  "files": [
    "builtin-search.ts",
    "emoji.ts",
    "encoding-japanese.d.ts",
    "index.ts",
    "keyboard.ts",
    "lib.d.ts",
    "marked.d.ts",
    "lint-message.ts",
    "lint-panel.ts",
    "markdown-preview.ts",
    "paw-filechooser.ts",
    "toc-dialog.ts"
  ]
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,7 +18,6 @@
     "index.ts",
     "keyboard.ts",
     "lib.d.ts",
-    "marked.d.ts",
     "lint-message.ts",
     "lint-panel.ts",
     "markdown-preview.ts",
```
