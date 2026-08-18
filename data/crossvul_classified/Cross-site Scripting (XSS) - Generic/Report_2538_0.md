# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in json
**Pair ID:** 2538_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2538_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```json
Lines 34-74 of the vulnerable file.

    "github-markdown-css": "^2.9.0",
    "he": "^1.1.1",
    "highlight.js": "^9.12.0",
    "js-yaml": "^3.10.0",
    "katex": "^0.8.3",
    "markdownlint": "^0.6.2",
    "marked": "github:rhysd/marked#emoji",
    "mermaid": "7.0.17",
    "mousetrap": "^1.6.1",
    "remark": "^8.0.0",
    "remark-lint": "^6.0.1",
    "remark-preset-lint-consistent": "^2.0.1",
    "remark-preset-lint-markdown-style-guide": "^2.1.1",
    "remark-preset-lint-recommended": "^3.0.1"
  },
  "devDependencies": {
    "@types/chokidar": "^1.7.3",
    "@types/empower": "^1.2.30",
    "@types/es6-promise": "0.0.33",
    "@types/he": "^0.5.29",
    "@types/highlight.js": "^9.12.1",
    "@types/js-yaml": "^3.9.1",
    "@types/katex": "0.5.0",
    "@types/mocha": "^2.2.44",
    "@types/mousetrap": "^1.5.34",
    "@types/node": "8.0.53",
    "@types/polymer": "^1.2.1",
    "@types/power-assert": "^1.4.29",
    "@types/power-assert-formatter": "^1.4.28",
    "@types/webcomponents.js": "^0.6.32",
    "@types/webdriverio": "^4.8.6",
    "asar": "^0.14.0",
    "bower": "^1.8.2",
    "electron-packager": "^10.1.0",
    "electron-rebuild": "^1.6.0",
    "intelli-espower-loader": "^1.0.1",
    "mocha": "^4.0.1",
    "nsp": "^3.1.0",
    "power-assert": "^1.4.4",
    "spectron": "^3.7.2",
    "touch": "^3.1.0",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -51,9 +51,10 @@
     "@types/empower": "^1.2.30",
     "@types/es6-promise": "0.0.33",
     "@types/he": "^0.5.29",
-    "@types/highlight.js": "^9.12.1",
+    "@types/highlight.js": "^9.12.2",
     "@types/js-yaml": "^3.9.1",
     "@types/katex": "0.5.0",
+    "@types/marked": "^0.3.0",
     "@types/mocha": "^2.2.44",
     "@types/mousetrap": "^1.5.34",
     "@types/node": "8.0.53",
```
