# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 4389_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4389_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 26-66 of the vulnerable file.

    "h3",
    "h4",
    "h5",
    "h6",  # headings
    "ol",
    "ul",
    "li",  # lists
    "table",
    "caption",
    "thead",
    "tbody",
    "th",
    "tr",
    "td",  # tables
    "div",
]
allowed_tags_permissive = allowed_tags_strict + [
    "video",
]


def allow_all(tag: str, name: str, value: str) -> bool:
    return True


allowed_attributes = allow_all
allowed_styles = [
    "color",
    "background-color",
    "height",
    "width",
    "text-align",
    "vertical-align",
    "float",
    "text-decoration",
    "margin",
    "padding",
    "line-height",
    "max-width",
    "min-width",
    "max-height",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,12 +43,40 @@
     "video",
 ]
 
+allowed_attributes = [
+    "align",
+    "alt",
+    "autoplay",
+    "background",
+    "bgcolor",
+    "border",
+    "class",
+    "colspan",
+    "controls",
+    "dir",
+    "height",
+    "hidden",
+    "href",
+    "hreflang",
+    "id",
+    "lang",
+    "loop",
+    "muted",
+    "poster",
+    "preload",
+    "rel",
+    "rowspan",
+    "scope",
+    "sizes",
+    "src",
+    "srcset",
+    "start",
+    "style",
+    "target",
+    "title",
+    "width",
+]
 
-def allow_all(tag: str, name: str, value: str) -> bool:
-    return True
-
-
-allowed_attributes = allow_all
 allowed_styles = [
     "color",
     "background-color",
```
