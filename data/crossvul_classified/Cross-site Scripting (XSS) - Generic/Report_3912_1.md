# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in json
**Pair ID:** 3912_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3912_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```json
Lines 48-88 of the vulnerable file.

    "apollo-server": "2.12.0",
    "apollo-server-express": "2.12.0",
    "auto-load": "3.0.4",
    "aws-sdk": "2.663.0",
    "azure-search-client": "3.1.5",
    "bcryptjs-then": "1.0.1",
    "bluebird": "3.7.2",
    "body-parser": "1.19.0",
    "chalk": "4.0.0",
    "cheerio": "1.0.0-rc.3",
    "chokidar": "3.4.0",
    "clean-css": "4.2.3",
    "compression": "1.7.4",
    "connect-session-knex": "1.6.0",
    "cookie-parser": "1.4.5",
    "cors": "2.8.5",
    "custom-error-instance": "2.1.1",
    "dependency-graph": "0.9.0",
    "diff": "4.0.2",
    "diff2html": "3.1.6",
    "dotize": "0.3.0",
    "elasticsearch6": "npm:@elastic/elasticsearch@6",
    "elasticsearch7": "npm:@elastic/elasticsearch@7",
    "emoji-regex": "9.0.0",
    "eventemitter2": "6.3.1",
    "express": "4.17.1",
    "express-brute": "1.0.1",
    "express-session": "1.17.1",
    "file-type": "14.2.0",
    "filesize": "6.1.0",
    "fs-extra": "9.0.0",
    "getos": "3.2.0",
    "graphql": "14.6.0",
    "graphql-list-fields": "2.0.2",
    "graphql-rate-limit-directive": "1.2.1",
    "graphql-subscriptions": "1.1.0",
    "graphql-tools": "4.0.7",
    "he": "1.2.0",
    "highlight.js": "10.0.0",
    "i18next": "19.4.3",
    "i18next-express-middleware": "2.0.0",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -65,6 +65,7 @@
     "dependency-graph": "0.9.0",
     "diff": "4.0.2",
     "diff2html": "3.1.6",
+    "dompurify": "2.0.10",
     "dotize": "0.3.0",
     "elasticsearch6": "npm:@elastic/elasticsearch@6",
     "elasticsearch7": "npm:@elastic/elasticsearch@7",
```
