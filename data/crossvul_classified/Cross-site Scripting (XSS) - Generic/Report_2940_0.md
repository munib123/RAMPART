# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 2940_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2940_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 1-34 of the vulnerable file.

# coding: utf-8
"""
    mistune
    ~~~~~~~

    The fastest markdown parser in pure Python with renderer feature.

    :copyright: (c) 2014 - 2017 by Hsiaoming Yang.
"""

import re
import inspect

__version__ = '0.8'
__author__ = 'Hsiaoming Yang <me@lepture.com>'
__all__ = [
    'BlockGrammar', 'BlockLexer',
    'InlineGrammar', 'InlineLexer',
    'Renderer', 'Markdown',
    'markdown', 'escape',
]


_key_pattern = re.compile(r'\s+')
_nonalpha_pattern = re.compile(r'\W')
_escape_pattern = re.compile(r'&(?!#?\w+;)')
_newline_pattern = re.compile(r'\r\n|\r')
_block_quote_leading_pattern = re.compile(r'^ *> ?', flags=re.M)
_block_code_leading_pattern = re.compile(r'^ {4}', re.M)
_inline_tags = [
    'a', 'em', 'strong', 'small', 's', 'cite', 'q', 'dfn', 'abbr', 'data',
    'time', 'code', 'var', 'samp', 'kbd', 'sub', 'sup', 'i', 'b', 'u', 'mark',
    'ruby', 'rt', 'rp', 'bdi', 'bdo', 'span', 'br', 'wbr', 'ins', 'del',
    'img', 'font',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,7 +11,7 @@
 import re
 import inspect
 
-__version__ = '0.8'
+__version__ = '0.8.1'
 __author__ = 'Hsiaoming Yang <me@lepture.com>'
 __all__ = [
     'BlockGrammar', 'BlockLexer',
@@ -48,7 +48,8 @@
 
 
 def _keyify(key):
-    return _key_pattern.sub(' ', key.lower())
+    key = escape(key.lower(), quote=True)
+    return _key_pattern.sub(' ', key)
 
 
 def escape(text, quote=False, smart_amp=True):
@@ -445,7 +446,8 @@
     inline_html = re.compile(
         r'^(?:%s|%s|%s)' % (
             r'<!--[\s\S]*?-->',
-            r'<(\w+%s)((?:%s)*?)\s*>([\s\S]*?)<\/\1>' % (_valid_end, _valid_attr),
+            r'<(\w+%s)((?:%s)*?)\s*>([\s\S]*?)<\/\1>' % (
+                _valid_end, _valid_attr),
             r'<\w+%s(?:%s)*?\s*\/?>' % (_valid_end, _valid_attr),
         )
     )
```
