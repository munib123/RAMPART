# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 1354_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1354_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 307-347 of the vulnerable file.

  var RETURN_DOM_IMPORT = false;

  /* Try to return a Trusted Type object instead of a string, retrun a string in
   * case Trusted Types are not supported  */
  var RETURN_TRUSTED_TYPE = false;

  /* Output should be free from DOM clobbering attacks? */
  var SANITIZE_DOM = true;

  /* Keep element content when removing element? */
  var KEEP_CONTENT = true;

  /* If a `Node` is passed to sanitize(), then performs sanitization in-place instead
   * of importing it into a new Document and returning a sanitized copy */
  var IN_PLACE = false;

  /* Allow usage of profiles like html, svg and mathMl */
  var USE_PROFILES = {};

  /* Tags to ignore content of when KEEP_CONTENT is true */
  var FORBID_CONTENTS = addToSet({}, ['annotation-xml', 'audio', 'colgroup', 'desc', 'foreignobject', 'head', 'math', 'mi', 'mn', 'mo', 'ms', 'mtext', 'script', 'style', 'template', 'thead', 'title', 'svg', 'video']);

  /* Tags that are safe for data: URIs */
  var DATA_URI_TAGS = addToSet({}, ['audio', 'video', 'img', 'source', 'image']);

  /* Attributes safe for values like "javascript:" */
  var URI_SAFE_ATTRIBUTES = null;
  var DEFAULT_URI_SAFE_ATTRIBUTES = addToSet({}, ['alt', 'class', 'for', 'id', 'label', 'name', 'pattern', 'placeholder', 'summary', 'title', 'value', 'style', 'xmlns']);

  /* Keep a reference to config to pass to hooks */
  var CONFIG = null;

  /* Ideally, do not touch anything below this line */
  /* ______________________________________________ */

  var formElement = document.createElement('form');

  /**
   * _parseConfig
   *
   * @param  {Object} cfg optional config literal
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -324,7 +324,7 @@
   var USE_PROFILES = {};
 
   /* Tags to ignore content of when KEEP_CONTENT is true */
-  var FORBID_CONTENTS = addToSet({}, ['annotation-xml', 'audio', 'colgroup', 'desc', 'foreignobject', 'head', 'math', 'mi', 'mn', 'mo', 'ms', 'mtext', 'script', 'style', 'template', 'thead', 'title', 'svg', 'video']);
+  var FORBID_CONTENTS = addToSet({}, ['annotation-xml', 'audio', 'colgroup', 'desc', 'foreignobject', 'head', 'math', 'mi', 'mn', 'mo', 'ms', 'mtext', 'script', 'style', 'template', 'thead', 'title', 'svg', 'video', 'xmp']);
 
   /* Tags that are safe for data: URIs */
   var DATA_URI_TAGS = addToSet({}, ['audio', 'video', 'img', 'source', 'image']);
@@ -870,6 +870,11 @@
         continue;
       }
 
+      /* Take care of an mXSS pattern using namespace switches */
+      if (/<\/(style|textarea)/.test(value)) {
+        _removeAttribute(name, currentNode);
+      }
+
       /* Sanitize attribute content to be template-safe */
       if (SAFE_FOR_TEMPLATES) {
         value = value.replace(MUSTACHE_EXPR$$1, ' ');
```
