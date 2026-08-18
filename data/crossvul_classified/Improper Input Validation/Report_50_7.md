# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 50_7
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `50_7`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 67-108 of the vulnerable file.

            raise ParameterError(ParameterError.USER_OR_SERIAL)

        f_result = func(*args, **kwds)
        return f_result

    return user_or_serial_wrapper


class check_user_or_serial_in_request(object):
    """
    Decorator to check user and serial in a request.
    If the request does not contain a serial number (serial) or a user
    (user) it will throw a ParameterError.
    """
    def __init__(self, request):
        self.request = request

    def __call__(self, func):
        @functools.wraps(func)
        def check_user_or_serial_in_request_wrapper(*args, **kwds):
            user = self.request.all_data.get("user")
            serial = self.request.all_data.get("serial")
            if not serial and not user:
                raise ParameterError(_("You need to specify a serial or a user."))
            f_result = func(*args, **kwds)
            return f_result

        return check_user_or_serial_in_request_wrapper


def check_copy_serials(func):
    """
    Decorator to check if the serial_from and serial_to exist.
    If the serials are not unique, we raise an error
    """
    from privacyidea.lib.token import get_tokens
    @functools.wraps(func)
    def check_serial_wrapper(*args, **kwds):
        tokenobject_list_from = get_tokens(serial=args[0])
        tokenobject_list_to = get_tokens(serial=args[1])
        if len(tokenobject_list_from) != 1:
            log.error("not a unique token to copy from found")
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -84,10 +84,15 @@
     def __call__(self, func):
         @functools.wraps(func)
         def check_user_or_serial_in_request_wrapper(*args, **kwds):
-            user = self.request.all_data.get("user")
-            serial = self.request.all_data.get("serial")
+            user = self.request.all_data.get("user", "").strip()
+            serial = self.request.all_data.get("serial", "").strip()
             if not serial and not user:
                 raise ParameterError(_("You need to specify a serial or a user."))
+            if "*" in serial:
+                raise ParameterError(_("Invalid serial number."))
+            if "%" in user:
+                raise ParameterError(_("Invalid user."))
+
             f_result = func(*args, **kwds)
             return f_result
 
```
