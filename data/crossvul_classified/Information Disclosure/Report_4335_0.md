# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in json
**Pair ID:** 4335_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4335_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```json
Lines 162-202 of the vulnerable file.

    "form-serialize": "0.7.2",
    "global": "4.4.0",
    "graphql": "14.6.0",
    "graphql-iso-date": "3.6.1",
    "graphql-tag": "2.10.3",
    "graphql-type-json": "0.3.1",
    "highlight.js": "9.18.1",
    "is-browser": "2.1.0",
    "isomorphic-unfetch": "3.0.0",
    "jsonwebtoken": "8.5.1",
    "load-script": "1.0.0",
    "lodash.omitby": "4.6.0",
    "markdown-it": "9.1.0",
    "markdown-it-mark": "3.0.0",
    "markdown-it-toc-and-anchor": "4.2.0",
    "mongoose": "5.9.5",
    "nodemailer": "5.1.1",
    "nodemailer-mailgun-transport": "1.4.0",
    "omit-deep-lodash": "1.1.4",
    "onefx": "1.8.5",
    "process": "0.11.10",
    "react-apollo": "2.5.8",
    "react-calendar-heatmap": "1.8.1",
    "react-dom": "16.13.1",
    "react-outside-click-handler": "1.3.0",
    "react-redux": "5.1.2",
    "react-router": "4.3.1",
    "react-router-dom": "4.3.1",
    "react-seo-meta-tags": "1.1.0",
    "react-tooltip": "3.11.6",
    "redux": "4.0.5",
    "reflect-metadata": "0.1.13",
    "rrule": "^2.6.4",
    "safe-json-globals": "2.1.0",
    "shader": "1.0.0",
    "ts-node": "8.6.2",
    "type-graphql": "0.17.6",
    "typescript": "4.0.3",
    "uuid": "3.4.0",
    "validator": "12.0.0",
    "web-push": "^3.4.3"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -179,6 +179,7 @@
     "nodemailer-mailgun-transport": "1.4.0",
     "omit-deep-lodash": "1.1.4",
     "onefx": "1.8.5",
+    "piexifjs": "^1.0.6",
     "process": "0.11.10",
     "react-apollo": "2.5.8",
     "react-calendar-heatmap": "1.8.1",
```
