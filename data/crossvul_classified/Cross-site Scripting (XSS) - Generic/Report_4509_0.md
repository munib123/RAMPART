# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4509_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4509_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1-26 of the vulnerable file.

const _ = require('lodash')
const cheerio = require('cheerio')
const uslug = require('uslug')
const pageHelper = require('../../../helpers/page')
const URL = require('url').URL

/* global WIKI */

module.exports = {
  async render() {
    const $ = cheerio.load(this.input, {
      decodeEntities: true
    })

    if ($.root().children().length < 1) {
      return ''
    }

    // --------------------------------
    // STEP: PRE
    // --------------------------------

    for (let child of _.reject(this.children, ['step', 'post'])) {
      const renderer = require(`../${_.kebabCase(child.key)}/renderer.js`)
      renderer.init($, child.config)
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,6 +3,8 @@
 const uslug = require('uslug')
 const pageHelper = require('../../../helpers/page')
 const URL = require('url').URL
+
+const mustacheRegExp = /(\{|&#x7b;?){2}(.+?)(\}|&#x7d;?){2}/i
 
 /* global WIKI */
 
@@ -231,6 +233,16 @@
     })
 
     // --------------------------------
+    // Wrap root text nodes
+    // --------------------------------
+
+    $('body').contents().toArray().forEach(item => {
+      if (item.type === 'text' && item.parent.name === 'body') {
+        $(item).wrap('<div></div>')
+      }
+    })
+
+    // --------------------------------
     // Escape mustache expresions
     // --------------------------------
 
@@ -239,7 +251,7 @@
       list.forEach(item => {
         if (item.type === 'text') {
           const rawText = $(item).text()
-          if (rawText.indexOf('{{') >= 0 && rawText.indexOf('}}') > 1) {
+          if (mustacheRegExp.test(rawText)) {
             $(item).parent().attr('v-pre', true)
           }
         } else {
```
