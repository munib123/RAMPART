# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 1354_8
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1354_8`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 243-283 of the vulnerable file.

  const FORBID_CONTENTS = addToSet({}, [
    'annotation-xml',
    'audio',
    'colgroup',
    'desc',
    'foreignobject',
    'head',
    'math',
    'mi',
    'mn',
    'mo',
    'ms',
    'mtext',
    'script',
    'style',
    'template',
    'thead',
    'title',
    'svg',
    'video',
  ]);

  /* Tags that are safe for data: URIs */
  const DATA_URI_TAGS = addToSet({}, [
    'audio',
    'video',
    'img',
    'source',
    'image',
  ]);

  /* Attributes safe for values like "javascript:" */
  let URI_SAFE_ATTRIBUTES = null;
  const DEFAULT_URI_SAFE_ATTRIBUTES = addToSet({}, [
    'alt',
    'class',
    'for',
    'id',
    'label',
    'name',
    'pattern',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -260,6 +260,7 @@
     'title',
     'svg',
     'video',
+    'xmp',
   ]);
 
   /* Tags that are safe for data: URIs */
@@ -893,6 +894,11 @@
         continue;
       }
 
+      /* Take care of an mXSS pattern using namespace switches */
+      if (/<\/(style|textarea)/.test(value)) {
+        _removeAttribute(name, currentNode);
+      }
+
       /* Sanitize attribute content to be template-safe */
       if (SAFE_FOR_TEMPLATES) {
         value = value.replace(MUSTACHE_EXPR, ' ');
```
