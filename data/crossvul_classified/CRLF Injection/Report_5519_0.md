# CrossVul Fix Pair: Improper Neutralization of CRLF Sequences ('CRLF Injection') in python
**Pair ID:** 5519_0
**Vulnerability Class:** CRLF Injection
**CWE:** CWE-93
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5519_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of CRLF Sequences ('CRLF Injection') - The product uses CRLF (carriage return line feeds) as a special element, e.

## Vulnerable Code
```python
Lines 1556-1597 of the vulnerable file.

        try:
            var = self.environ['bottle.request.ext.%s' % name]
            return var.__get__(self) if hasattr(var, '__get__') else var
        except KeyError:
            raise AttributeError('Attribute %r not defined.' % name)

    def __setattr__(self, name, value):
        if name == 'environ': return object.__setattr__(self, name, value)
        key = 'bottle.request.ext.%s' % name
        if key in self.environ:
            raise AttributeError("Attribute already defined: %s" % name)
        self.environ[key] = value

    def __delattr__(self, name, value):
        try:
            del self.environ['bottle.request.ext.%s' % name]
        except KeyError:
            raise AttributeError("Attribute not defined: %s" % name)


def _hkey(s):
    return s.title().replace('_', '-')


class HeaderProperty(object):
    def __init__(self, name, reader=None, writer=str, default=''):
        self.name, self.default = name, default
        self.reader, self.writer = reader, writer
        self.__doc__ = 'Current value of the %r header.' % name.title()

    def __get__(self, obj, _):
        if obj is None: return self
        value = obj.headers.get(self.name, self.default)
        return self.reader(value) if self.reader else value

    def __set__(self, obj, value):
        obj.headers[self.name] = self.writer(value)

    def __delete__(self, obj):
        del obj.headers[self.name]


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1573,9 +1573,16 @@
             raise AttributeError("Attribute not defined: %s" % name)
 
 
-def _hkey(s):
-    return s.title().replace('_', '-')
-
+def _hkey(key):
+    if '\n' in key or '\r' in key or '\0' in key:
+        raise ValueError("Header names must not contain control characters: %r" % key)
+    return key.title().replace('_', '-')
+
+def _hval(value):
+    value = value if isinstance(value, unicode) else str(value)
+    if '\n' in value or '\r' in value or '\0' in value:
+        raise ValueError("Header value must not contain control characters: %r" % value)
+    return value
 
 class HeaderProperty(object):
     def __init__(self, name, reader=None, writer=str, default=''):
@@ -2170,7 +2177,6 @@
             return super(FormsDict, self).__getattr__(name)
         return self.getunicode(name, default=default)
 
-
 class HeaderDict(MultiDict):
     """ A case-insensitive version of :class:`MultiDict` that defaults to
         replace the old value instead of appending it. """
@@ -2189,16 +2195,13 @@
         return self.dict[_hkey(key)][-1]
 
     def __setitem__(self, key, value):
-        self.dict[_hkey(key)] = [value if isinstance(value, unicode) else
-                                 str(value)]
+        self.dict[_hkey(key)] = [_hval(value)]
 
     def append(self, key, value):
-        self.dict.setdefault(_hkey(key), []).append(
-            value if isinstance(value, unicode) else str(value))
+        self.dict.setdefault(_hkey(key), []).append(_hval(value))
 
     def replace(self, key, value):
-        self.dict[_hkey(key)] = [value if isinstance(value, unicode) else
-                                 str(value)]
+        self.dict[_hkey(key)] = [_hval(value)]
 
     def getall(self, key):
         return self.dict.get(_hkey(key)) or []
@@ -2207,7 +2210,7 @@
         return MultiDict.get(self, _hkey(key), default, index)
 
     def filter(self, names):
-        for name in [_hkey(n) for n in names]:
+        for name in (_hkey(n) for n in names):
             if name in self.dict:
                 del self.dict[name]
 
```
