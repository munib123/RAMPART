# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in json
**Pair ID:** 4683_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4683_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```json
Lines 55-95 of the vulnerable file.

    "joplin-turndown-plugin-gfm": "^1.0.12",
    "json-stringify-safe": "^5.0.1",
    "jssha": "^2.3.0",
    "katex": "^0.11.1",
    "levenshtein": "^1.0.5",
    "markdown-it": "^10.0.0",
    "markdown-it-abbr": "^1.0.4",
    "markdown-it-anchor": "^5.2.5",
    "markdown-it-deflist": "^2.0.3",
    "markdown-it-emoji": "^1.4.0",
    "markdown-it-expand-tabs": "^1.0.13",
    "markdown-it-footnote": "^3.0.2",
    "markdown-it-ins": "^3.0.0",
    "markdown-it-mark": "^3.0.0",
    "markdown-it-multimd-table": "^4.0.1",
    "markdown-it-sub": "^1.0.0",
    "markdown-it-sup": "^1.0.0",
    "markdown-it-toc-done-right": "^4.1.0",
    "md5": "^2.2.1",
    "md5-file": "^4.0.0",
    "mime": "^2.0.3",
    "moment": "^2.24.0",
    "multiparty": "^4.2.1",
    "node-emoji": "^1.8.1",
    "node-fetch": "^1.7.1",
    "node-persist": "^2.1.0",
    "patch-package": "^6.2.0",
    "promise": "^7.1.1",
    "proper-lockfile": "^2.0.1",
    "query-string": "4.3.4",
    "read-chunk": "^2.1.0",
    "redux": "^3.7.2",
    "request": "^2.88.0",
    "sax": "^1.2.4",
    "server-destroy": "^1.0.1",
    "sharp": "^0.23.2",
    "sprintf-js": "^1.1.1",
    "sqlite3": "^4.1.1",
    "string-padding": "^1.0.2",
    "string-to-stream": "^1.1.0",
    "strip-ansi": "^4.0.0",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -72,6 +72,7 @@
     "markdown-it-toc-done-right": "^4.1.0",
     "md5": "^2.2.1",
     "md5-file": "^4.0.0",
+    "memory-cache": "^0.2.0",
     "mime": "^2.0.3",
     "moment": "^2.24.0",
     "multiparty": "^4.2.1",
@@ -104,7 +105,8 @@
     "valid-url": "^1.0.9",
     "word-wrap": "^1.2.3",
     "xml2js": "^0.4.19",
-    "yargs-parser": "^7.0.0"
+    "yargs-parser": "^7.0.0",
+    "node-html-parser": "^1.2.4"
   },
   "devDependencies": {
     "jasmine": "^3.5.0"
```
