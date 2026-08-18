# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 1645_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1645_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 322-362 of the vulnerable file.

    """Decorate methods with this to return GitHub style JSON errors.
    
    This should be used on any JSON API on any handler method that can raise HTTPErrors.
    
    This will grab the latest HTTPError exception using sys.exc_info
    and then:
    
    1. Set the HTTP status code based on the HTTPError
    2. Create and return a JSON body with a message field describing
       the error in a human readable form.
    """
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        try:
            result = method(self, *args, **kwargs)
        except web.HTTPError as e:
            status = e.status_code
            message = e.log_message
            self.log.warn(message)
            self.set_status(e.status_code)
            self.finish(json.dumps(dict(message=message)))
        except Exception:
            self.log.error("Unhandled error in API request", exc_info=True)
            status = 500
            message = "Unknown server error"
            t, value, tb = sys.exc_info()
            self.set_status(status)
            tb_text = ''.join(traceback.format_exception(t, value, tb))
            reply = dict(message=message, traceback=tb_text)
            self.finish(json.dumps(reply))
        else:
            return result
    return wrapper



#-----------------------------------------------------------------------------
# File handler
#-----------------------------------------------------------------------------

# to minimize subclass changes:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -339,6 +339,7 @@
             message = e.log_message
             self.log.warn(message)
             self.set_status(e.status_code)
+            self.set_header('Content-Type', 'application/json')
             self.finish(json.dumps(dict(message=message)))
         except Exception:
             self.log.error("Unhandled error in API request", exc_info=True)
@@ -348,6 +349,7 @@
             self.set_status(status)
             tb_text = ''.join(traceback.format_exception(t, value, tb))
             reply = dict(message=message, traceback=tb_text)
+            self.set_header('Content-Type', 'application/json')
             self.finish(json.dumps(reply))
         else:
             return result
```
