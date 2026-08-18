# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in python
**Pair ID:** 4110_3
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4110_3`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```python
Lines 1-17 of the vulnerable file.

import re

import stringcase


def snake_case(value: str) -> str:
    value = re.sub(r"([A-Z]{2,})([A-Z][a-z]|[ -_]|$)", lambda m: m.group(1).title() + m.group(2), value.strip())
    value = re.sub(r"(^|[ _-])([A-Z])", lambda m: m.group(1) + m.group(2).lower(), value)
    return stringcase.snakecase(value)


def pascal_case(value: str) -> str:
    return stringcase.pascalcase(value)


def spinal_case(value: str) -> str:
    return stringcase.spinalcase(value)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,15 +3,23 @@
 import stringcase
 
 
-def snake_case(value: str) -> str:
+def _sanitize(value: str) -> str:
+    return re.sub(r"[^\w _-]+", "", value)
+
+
+def group_title(value: str) -> str:
     value = re.sub(r"([A-Z]{2,})([A-Z][a-z]|[ -_]|$)", lambda m: m.group(1).title() + m.group(2), value.strip())
     value = re.sub(r"(^|[ _-])([A-Z])", lambda m: m.group(1) + m.group(2).lower(), value)
-    return stringcase.snakecase(value)
+    return value
+
+
+def snake_case(value: str) -> str:
+    return stringcase.snakecase(group_title(_sanitize(value)))
 
 
 def pascal_case(value: str) -> str:
-    return stringcase.pascalcase(value)
+    return stringcase.pascalcase(_sanitize(value))
 
 
-def spinal_case(value: str) -> str:
-    return stringcase.spinalcase(value)
+def kebab_case(value: str) -> str:
+    return stringcase.spinalcase(group_title(_sanitize(value)))
```
