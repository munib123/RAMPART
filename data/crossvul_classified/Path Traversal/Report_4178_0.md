# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in javascript
**Pair ID:** 4178_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4178_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```javascript
Lines 1-28 of the vulnerable file.

const qs = require('querystring')
const _ = require('lodash')
const crypto = require('crypto')
const path = require('path')

const localeSegmentRegex = /^[A-Z]{2}(-[A-Z]{2})?$/i
const localeFolderRegex = /^([a-z]{2}(?:-[a-z]{2})?\/)?(.*)/i

const contentToExt = {
  markdown: 'md',
  html: 'html'
}
const extToContent = _.invert(contentToExt)

/* global WIKI */

module.exports = {
  /**
   * Parse raw url path and make it safe
   */
  parsePath (rawPath, opts = {}) {
    let pathObj = {
      locale: WIKI.config.lang.code,
      path: 'home',
      private: false,
      privateNS: '',
      explicitLocale: false
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,6 +5,8 @@
 
 const localeSegmentRegex = /^[A-Z]{2}(-[A-Z]{2})?$/i
 const localeFolderRegex = /^([a-z]{2}(?:-[a-z]{2})?\/)?(.*)/i
+// eslint-disable-next-line no-control-regex
+const unsafeCharsRegex = /[\x00-\x1f\x80-\x9f\\"|<>:*?]/
 
 const contentToExt = {
   markdown: 'md',
@@ -30,10 +32,14 @@
     // Clean Path
     rawPath = _.trim(qs.unescape(rawPath))
     if (_.startsWith(rawPath, '/')) { rawPath = rawPath.substring(1) }
+    rawPath = rawPath.replace(unsafeCharsRegex, '')
     if (rawPath === '') { rawPath = 'home' }
 
     // Extract Info
-    let pathParts = _.filter(_.split(rawPath, '/'), p => !_.isEmpty(p))
+    let pathParts = _.filter(_.split(rawPath, '/'), p => {
+      p = _.trim(p)
+      return !_.isEmpty(p) && p !== '..' && p !== '.'
+    })
     if (pathParts[0].length === 1) {
       pathParts.shift()
     }
@@ -73,7 +79,7 @@
       ['date', page.updatedAt],
       ['tags', page.tags ? page.tags.map(t => t.tag).join(', ') : ''],
       ['editor', page.editorKey],
-      ['dateCreated', page.createdAt],
+      ['dateCreated', page.createdAt]
     ]
     switch (page.contentType) {
       case 'markdown':
```
