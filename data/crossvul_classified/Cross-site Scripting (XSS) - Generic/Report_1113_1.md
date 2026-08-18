# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 1113_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1113_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 16-56 of the vulnerable file.

    '"\\u003Cscript type=\\"application\\u002Fjavascript\\"\\u003E\\u2028\\u2029\\nvar a = 0;\\nvar b = 1; a \\u003E 1;\\n\\u003C\\u002Fscript\\u003E"'
  ],
  'number': [
    3.1415,
    '3.1415'
  ],
  'boolean': [
    true,
    'true'
  ],
  'undefined': [
    undefined,
    'undefined'
  ],
  'null': [
    null,
    'null'
  ],
  'regex': [
    /test(?:it)?/ig,
    '/test(?:it)?/gi'
  ],
  'object': [
    { a: 1, b: 2 },
    '{a: 1, b: 2}'
  ],
  'empty object': [
    {},
    '{}'
  ],
  'object with backslash': [
    { backslash: '\\' },
    '{backslash: "\\\\"}'
  ],
  'object of primitives': [
    {
      one: true,
      two: false,
      'thr-ee': undefined,
      four: 1,
      '5': 3.1415,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,7 +33,7 @@
   ],
   'regex': [
     /test(?:it)?/ig,
-    '/test(?:it)?/gi'
+    'new RegExp("test(?:it)?", "gi")'
   ],
   'object': [
     { a: 1, b: 2 },
@@ -138,6 +138,14 @@
     new Float64Array([1e12, 2000000, 3.1415, -4.9e2, 5]),
     'new Float64Array([1000000000000, 2000000, 3.1415, -490, 5])',
     'toString'
+  ],
+  'regexXss': [
+    /[</script><script>alert('xss')//]/i,
+    'new RegExp("[</script><script>alert(\'xss\')//]", "i")'
+  ],
+  'regex no flags': [
+    /abc/,
+    'new RegExp("abc", "")'
   ]
 }
 
```
