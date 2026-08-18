# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 3890_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3890_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 1-31 of the vulnerable file.

import difflib

from bs4 import BeautifulSoup
from django.utils.encoding import force_str
from django.utils.html import escape, format_html, format_html_join
from django.utils.safestring import mark_safe
from django.utils.text import capfirst
from django.utils.translation import ugettext_lazy as _

from wagtail.core import blocks


class FieldComparison:
    is_field = True
    is_child_relation = False

    def __init__(self, field, obj_a, obj_b):
        self.field = field
        self.val_a = field.value_from_object(obj_a)
        self.val_b = field.value_from_object(obj_b)

    def field_label(self):
        """
        Returns a label for this field to be displayed to the user
        """
        verbose_name = getattr(self.field, 'verbose_name', None)

        if verbose_name is None:
            # Relations don't have a verbose_name
            verbose_name = self.field.name.replace('_', ' ')

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,6 +10,11 @@
 from wagtail.core import blocks
 
 
+def text_from_html(val):
+    # Return the unescaped text content of an HTML string
+    return BeautifulSoup(force_str(val), 'html5lib').getText()
+
+
 class FieldComparison:
     is_field = True
     is_child_relation = False
@@ -52,15 +57,18 @@
 class RichTextFieldComparison(TextFieldComparison):
     def htmldiff(self):
         return diff_text(
-            BeautifulSoup(force_str(self.val_a), 'html5lib').getText(),
-            BeautifulSoup(force_str(self.val_b), 'html5lib').getText()
+            text_from_html(self.val_a),
+            text_from_html(self.val_b)
         ).to_html()
 
 
 def get_comparison_class_for_block(block):
     if hasattr(block, 'get_comparison_class'):
         return block.get_comparison_class()
-    elif isinstance(block, blocks.CharBlock):
+    elif isinstance(block, (blocks.CharBlock, blocks.TextBlock)):
+        return CharBlockComparison
+    elif isinstance(block, blocks.RawHTMLBlock):
+        # Compare raw HTML blocks as if they were plain text, so that tags are shown explicitly
         return CharBlockComparison
     elif isinstance(block, blocks.RichTextBlock):
         return RichTextBlockComparison
@@ -89,7 +97,19 @@
         return self.val_a != self.val_b
 
     def htmlvalue(self, val):
-        return self.block.render_basic(val)
+        """
+        Return an HTML representation of this block that is safe to be included
+        in comparison views
+        """
+        return escape(text_from_html(self.block.render_basic(val)))
+
+    def htmldiff(self):
+        html_val_a = self.block.render_basic(self.val_a)
+        html_val_b = self.block.render_basic(self.val_b)
+        return diff_text(
+            text_from_html(html_val_a),
+            text_from_html(html_val_b)
+        ).to_html()
 
 
 class CharBlockComparison(BlockComparison):
@@ -99,13 +119,12 @@
             force_str(self.val_b)
         ).to_html()
 
+    def htmlvalue(self, val):
+        return escape(val)
+
 
 class RichTextBlockComparison(BlockComparison):
-    def htmldiff(self):
-        return diff_text(
-            BeautifulSoup(force_str(self.val_a), 'html5lib').getText(),
-            BeautifulSoup(force_str(self.val_b), 'html5lib').getText()
-        ).to_html()
+    pass
 
 
 class StructBlockComparison(BlockComparison):
@@ -219,8 +238,8 @@
         else:
             # Fall back to diffing the HTML representation
             return diff_text(
-                BeautifulSoup(force_str(self.val_a), 'html5lib').getText(),
-                BeautifulSoup(force_str(self.val_b), 'html5lib').getText()
+                text_from_html(self.val_a),
+                text_from_html(self.val_b)
             ).to_html()
 
 
```
