# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in json
**Pair ID:** 4391_2
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4391_2`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```json
Lines 26-66 of the vulnerable file.

    "base64url": "^3.0.0",
    "body-parser": "^1.15.2",
    "bootstrap": "^3.4.0",
    "bootstrap-validator": "^0.11.8",
    "chance": "^1.0.4",
    "cheerio": "^0.22.0",
    "codemirror": "git+https://github.com/hedgedoc/CodeMirror.git",
    "compression": "^1.6.2",
    "connect-flash": "^0.1.1",
    "connect-session-sequelize": "^6.0.0",
    "cookie": "^0.4.0",
    "cookie-parser": "^1.4.3",
    "deep-freeze": "^0.0.1",
    "diff-match-patch": "git+https://github.com/hackmdio/diff-match-patch.git",
    "ejs": "^2.5.5",
    "emojify.js": "^1.1.0",
    "escape-html": "^1.0.3",
    "express": ">=4.14",
    "express-session": "^1.14.2",
    "file-saver": "^1.3.3",
    "flowchart.js": "^1.6.4",
    "fork-awesome": "^1.1.3",
    "formidable": "^1.0.17",
    "gist-embed": "^2.6.0",
    "graceful-fs": "^4.1.11",
    "handlebars": "^4.5.2",
    "helmet": "^3.21.1",
    "highlight.js": "^9.12.0",
    "i18n": "^0.13.0",
    "imgur": "git+https://github.com/hackmdio/node-imgur.git",
    "ionicons": "^2.0.1",
    "jquery": "^3.5.1",
    "jquery-mousewheel": "^3.1.13",
    "jquery-ui": "^1.12.1",
    "js-cookie": "^2.1.3",
    "js-sequence-diagrams": "git+https://github.com/hedgedoc/js-sequence-diagrams.git",
    "js-yaml": "^3.13.1",
    "jsdom-nogyp": "^0.8.3",
    "keymaster": "^1.6.2",
    "list.js": "^1.5.0",
    "lodash": "^4.17.20",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,6 +43,7 @@
     "express": ">=4.14",
     "express-session": "^1.14.2",
     "file-saver": "^1.3.3",
+    "file-type": "^16.1.0",
     "flowchart.js": "^1.6.4",
     "fork-awesome": "^1.1.3",
     "formidable": "^1.0.17",
@@ -111,6 +112,7 @@
     "readline-sync": "^1.4.7",
     "request": "^2.88.0",
     "reveal.js": "^3.9.2",
+    "rimraf": "^3.0.2",
     "scrypt-async": "^2.0.1",
     "scrypt-kdf": "^2.0.1",
     "select2": "^3.5.2-browserify",
```
