# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in python
**Pair ID:** 4177_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4177_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```python
Lines 47-73 of the vulnerable file.

def get(key):
    return backend.get(key)


def set(key, value):
    backend.set(key, value)


def get_all():
    return backend.get_all()


def get_all_non_sensitive():
    sensitive = backend.get('sensitive_fields')
    config = backend.get_all()
    for field in sensitive:
        del config[field]
    return config


def set_bulk(values: dict):
    for key, value in values.items():
        set(key, value)


def add_plugin_config(name, config):
    DEFAULT_CONFIG[name] = config
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -64,6 +64,10 @@
     return config
 
 
+def is_sensitive(key):
+    return key in backend.get('sensitive_fields')
+
+
 def set_bulk(values: dict):
     for key, value in values.items():
         set(key, value)
```
