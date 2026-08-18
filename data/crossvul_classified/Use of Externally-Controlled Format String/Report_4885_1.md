# CrossVul Fix Pair: Use of Externally-Controlled Format String in python
**Pair ID:** 4885_1
**Vulnerability Class:** Use of Externally-Controlled Format String
**CWE:** CWE-134
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4885_1`)

## Vulnerability Information & PoC

## Description
Use of Externally-Controlled Format String - When an attacker can modify an externally-controlled format string, this can lead to buffer overflows, denial of service, or data representation problems.

## Vulnerable Code
```python
Lines 1-37 of the vulnerable file.

# -*- coding: utf-8 -*-
"""
    jinja2.sandbox
    ~~~~~~~~~~~~~~

    Adds a sandbox layer to Jinja as it was the default behavior in the old
    Jinja 1 releases.  This sandbox is slightly different from Jinja 1 as the
    default behavior is easier to use.

    The behavior can be changed by subclassing the environment.

    :copyright: (c) 2010 by the Jinja Team.
    :license: BSD.
"""
import types
import operator
from jinja2.environment import Environment
from jinja2.exceptions import SecurityError
from jinja2._compat import string_types, PY2


#: maximum number of items a range may produce
MAX_RANGE = 100000

#: attributes of function objects that are considered unsafe.
if PY2:
    UNSAFE_FUNCTION_ATTRIBUTES = set(['func_closure', 'func_code', 'func_dict',
                                      'func_defaults', 'func_globals'])
else:
    # On versions > python 2 the special attributes on functions are gone,
    # but they remain on methods and generators for whatever reason.
    UNSAFE_FUNCTION_ATTRIBUTES = set()


#: unsafe method attributes.  function attributes are unsafe for methods too
UNSAFE_METHOD_ATTRIBUTES = set(['im_class', 'im_func', 'im_self'])

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,9 +14,17 @@
 """
 import types
 import operator
+from collections import Mapping
 from jinja2.environment import Environment
 from jinja2.exceptions import SecurityError
-from jinja2._compat import string_types, PY2
+from jinja2._compat import string_types, text_type, PY2
+from jinja2.utils import Markup
+
+has_format = False
+if hasattr(text_type, 'format'):
+    from markupsafe import EscapeFormatter
+    from string import Formatter
+    has_format = True
 
 
 #: maximum number of items a range may produce
@@ -37,6 +45,12 @@
 
 #: unsafe generator attirbutes.
 UNSAFE_GENERATOR_ATTRIBUTES = set(['gi_frame', 'gi_code'])
+
+#: unsafe attributes on coroutines
+UNSAFE_COROUTINE_ATTRIBUTES = set(['cr_frame', 'cr_code'])
+
+#: unsafe attributes on async generators
+UNSAFE_ASYNC_GENERATOR_ATTRIBUTES = set(['ag_code', 'ag_frame'])
 
 import warnings
 
@@ -94,6 +108,49 @@
 )
 
 
+class _MagicFormatMapping(Mapping):
+    """This class implements a dummy wrapper to fix a bug in the Python
+    standard library for string formatting.
+
+    See http://bugs.python.org/issue13598 for information about why
+    this is necessary.
+    """
+
+    def __init__(self, args, kwargs):
+        self._args = args
+        self._kwargs = kwargs
+        self._last_index = 0
+
+    def __getitem__(self, key):
+        if key == '':
+            idx = self._last_index
+            self._last_index += 1
+            try:
+                return self._args[idx]
+            except LookupError:
+                pass
+            key = str(idx)
+        return self._kwargs[key]
+
+    def __iter__(self):
+        return iter(self._kwargs)
+
+    def __len__(self):
+        return len(self._kwargs)
+
+
+def inspect_format_method(callable):
+    if not has_format:
+        return None
+    if not isinstance(callable, (types.MethodType,
+                                 types.BuiltinMethodType)) or \
+       callable.__name__ != 'format':
+        return None
+    obj = callable.__self__
+    if isinstance(obj, string_types):
+        return obj
+
+
 def safe_range(*args):
     """A range that can't generate ranges with a length of more than
     MAX_RANGE items.
@@ -144,6 +201,12 @@
         return True
     elif isinstance(obj, types.GeneratorType):
         if attr in UNSAFE_GENERATOR_ATTRIBUTES:
+            return True
+    elif hasattr(types, 'CoroutineType') and isinstance(obj, types.CoroutineType):
+        if attr in UNSAFE_COROUTINE_ATTRIBUTES:
+            return True
+    elif hasattr(types, 'AsyncGeneratorType') and isinstance(obj, types.AsyncGeneratorType):
+        if attri in UNSAFE_ASYNC_GENERATOR_ATTRIBUTES:
             return True
     return attr.startswith('__')
 
@@ -183,8 +246,8 @@
     attributes or functions are safe to access.
 
     If the template tries to access insecure code a :exc:`SecurityError` is
-    raised.  However also other exceptions may occour during the rendering so
-    the caller has to ensure that all exceptions are catched.
+    raised.  However also other exceptions may occur during the rendering so
+    the caller has to ensure that all exceptions are caught.
     """
     sandboxed = True
 
@@ -346,8 +409,24 @@
             obj.__class__.__name__
         ), name=attribute, obj=obj, exc=SecurityError)
 
+    def format_string(self, s, args, kwargs):
+        """If a format call is detected, then this is routed through this
+        method so that our safety sandbox can be used for it.
+        """
+        if isinstance(s, Markup):
+            formatter = SandboxedEscapeFormatter(self, s.escape)
+        else:
+            formatter = SandboxedFormatter(self)
+        kwargs = _MagicFormatMapping(args, kwargs)
+        rv = formatter.vformat(s, args, kwargs)
+        return type(s)(rv)
+
     def call(__self, __context, __obj, *args, **kwargs):
         """Call an object from sandboxed code."""
+        fmt = inspect_format_method(__obj)
+        if fmt is not None:
+            return __self.format_string(fmt, args, kwargs)
+
         # the double prefixes are to avoid double keyword argument
         # errors when proxying the call.
         if not __self.is_safe_callable(__obj):
@@ -365,3 +444,37 @@
         if not SandboxedEnvironment.is_safe_attribute(self, obj, attr, value):
             return False
         return not modifies_known_mutable(obj, attr)
+
+
+if has_format:
+    # This really is not a public API apparenlty.
+    try:
+        from _string import formatter_field_name_split
+    except ImportError:
+        def formatter_field_name_split(field_name):
+            return field_name._formatter_field_name_split()
+
+    class SandboxedFormatterMixin(object):
+
+        def __init__(self, env):
+            self._env = env
+
+        def get_field(self, field_name, args, kwargs):
+            first, rest = formatter_field_name_split(field_name)
+            obj = self.get_value(first, args, kwargs)
+            for is_attr, i in rest:
+                if is_attr:
+                    obj = self._env.getattr(obj, i)
+                else:
+                    obj = self._env.getitem(obj, i)
+            return obj, first
+
+    class SandboxedFormatter(SandboxedFormatterMixin, Formatter):
+        def __init__(self, env):
+            SandboxedFormatterMixin.__init__(self, env)
+            Formatter.__init__(self)
+
+    class SandboxedEscapeFormatter(SandboxedFormatterMixin, EscapeFormatter):
+        def __init__(self, env, escape):
+            SandboxedFormatterMixin.__init__(self, env)
+            EscapeFormatter.__init__(self, escape)
```
