# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in python
**Pair ID:** 1775_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1775_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```python
Lines 11-51 of the vulnerable file.

from django.utils.translation import (
    check_for_language, get_language, to_locale,
)

# format_cache is a mapping from (format_type, lang) to the format string.
# By using the cache, it is possible to avoid running get_format_modules
# repeatedly.
_format_cache = {}
_format_modules_cache = {}

ISO_INPUT_FORMATS = {
    'DATE_INPUT_FORMATS': ['%Y-%m-%d'],
    'TIME_INPUT_FORMATS': ['%H:%M:%S', '%H:%M:%S.%f', '%H:%M'],
    'DATETIME_INPUT_FORMATS': [
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d %H:%M:%S.%f',
        '%Y-%m-%d %H:%M',
        '%Y-%m-%d'
    ],
}


def reset_format_cache():
    """Clear any cached formats.

    This method is provided primarily for testing purposes,
    so that the effects of cached formats can be removed.
    """
    global _format_cache, _format_modules_cache
    _format_cache = {}
    _format_modules_cache = {}


def iter_format_modules(lang, format_module_path=None):
    """
    Does the heavy lifting of finding format modules.
    """
    if not check_for_language(lang):
        return

    if format_module_path is None:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,6 +28,24 @@
         '%Y-%m-%d'
     ],
 }
+
+
+FORMAT_SETTINGS = frozenset([
+    'DECIMAL_SEPARATOR',
+    'THOUSAND_SEPARATOR',
+    'NUMBER_GROUPING',
+    'FIRST_DAY_OF_WEEK',
+    'MONTH_DAY_FORMAT',
+    'TIME_FORMAT',
+    'DATE_FORMAT',
+    'DATETIME_FORMAT',
+    'SHORT_DATE_FORMAT',
+    'SHORT_DATETIME_FORMAT',
+    'YEAR_MONTH_FORMAT',
+    'DATE_INPUT_FORMATS',
+    'TIME_INPUT_FORMATS',
+    'DATETIME_INPUT_FORMATS',
+])
 
 
 def reset_format_cache():
@@ -92,6 +110,8 @@
     be localized (or not), overriding the value of settings.USE_L10N.
     """
     format_type = force_str(format_type)
+    if format_type not in FORMAT_SETTINGS:
+        return format_type
     if use_l10n or (use_l10n is None and settings.USE_L10N):
         if lang is None:
             lang = get_language()
```
