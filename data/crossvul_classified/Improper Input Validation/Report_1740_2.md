# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 1740_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1740_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 38-80 of the vulnerable file.

    """
    required_keys = {
        "name",
        "path",
        "type",
        "writable",
        "created",
        "last_modified",
        "mimetype",
        "content",
        "format",
    }
    missing = required_keys - set(model.keys())
    if missing:
        raise web.HTTPError(
            500,
            u"Missing Model Keys: {missing}".format(missing=missing),
        )

    maybe_none_keys = ['content', 'format']
    if model['type'] == 'file':
        # mimetype should be populated only for file models
        maybe_none_keys.append('mimetype')
    if expect_content:
        errors = [key for key in maybe_none_keys if model[key] is None]
        if errors:
            raise web.HTTPError(
                500,
                u"Keys unexpectedly None: {keys}".format(keys=errors),
            )
    else:
        errors = {
            key: model[key]
            for key in maybe_none_keys
            if model[key] is not None
        }
        if errors:
            raise web.HTTPError(
                500,
                u"Keys unexpectedly not None: {keys}".format(keys=errors),
            )


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -55,9 +55,6 @@
         )
 
     maybe_none_keys = ['content', 'format']
-    if model['type'] == 'file':
-        # mimetype should be populated only for file models
-        maybe_none_keys.append('mimetype')
     if expect_content:
         errors = [key for key in maybe_none_keys if model[key] is None]
         if errors:
```
