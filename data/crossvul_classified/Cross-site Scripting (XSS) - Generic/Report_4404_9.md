# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4404_9
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4404_9`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1058-1090 of the vulnerable file.

      "title": "Tests against attribute-based mXSS behavior 3/3",
      "payload": "<math><annotation-xml encoding=\"text/html\"><p><style><p title=\"</style><iframe onload&#x3d;alert(1)<!--\"></style>",
      "expected": [
          ""
      ]
  }, {
      "title": "Tests against removal-based mXSS behavior 1/2",
      "payload": "<xmp><svg><b><style><b title='</style><img>'>",
      "expected": [
          ""
      ]
  }, {
      "title": "Tests against removal-based mXSS behavior 2/2",
      "payload": "<noembed><svg><b><style><b title='</style><img>'>",
      "expected": [
          "",
          "<svg><b><style><b></b></style></b></svg>",
          "<svg></svg><b><style><b title='</style><img>'&gt;</b>"
      ]
  }, {
      "title": "Tests against nesting-based mXSS behavior 1/1",
      "payload": "<form><math><mtext></form><form><mglyph><style><img>",
      "expected": [
          "<form></form>"
      ]
  }, {
      "title": "Tests against proper handling of leading whitespaces",
      "payload": " ",
      "expected": [
          " "
      ]
  }
];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1075,10 +1075,16 @@
           "<svg></svg><b><style><b title='</style><img>'&gt;</b>"
       ]
   }, {
-      "title": "Tests against nesting-based mXSS behavior 1/1",
+      "title": "Tests against nesting-based mXSS behavior 1/2",
       "payload": "<form><math><mtext></form><form><mglyph><style><img>",
       "expected": [
           "<form></form>"
+      ]
+  }, {
+      "title": "Tests against nesting-based mXSS behavior 2/2",
+      "payload": "<math><mtext><table><mglyph><style><math>CLICKME</math>",
+      "expected": [
+          ""
       ]
   }, {
       "title": "Tests against proper handling of leading whitespaces",
```
