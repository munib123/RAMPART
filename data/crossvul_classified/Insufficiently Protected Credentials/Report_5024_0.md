# CrossVul Fix Pair: Credentials Management Errors in python
**Pair ID:** 5024_0
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-255
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5024_0`)

## Vulnerability Information & PoC

## Description
Credentials Management Errors

## Vulnerable Code
```python
Lines 169-209 of the vulnerable file.

    - cookies
    - get_vars
    - post_vars
    - vars
    - folder
    - application
    - function
    - args
    - extension
    - now: datetime.datetime.now()
    - utcnow : datetime.datetime.utcnow()
    - is_local
    - is_https
    - restful()
    """

    def __init__(self, env):
        Storage.__init__(self)
        self.env = Storage(env)
        self.env.web2py_path = global_settings.applications_parent
        self.env.update(global_settings)
        self.cookies = Cookie.SimpleCookie()
        self._get_vars = None
        self._post_vars = None
        self._vars = None
        self._body = None
        self.folder = None
        self.application = None
        self.function = None
        self.args = List()
        self.extension = 'html'
        self.now = datetime.datetime.now()
        self.utcnow = datetime.datetime.utcnow()
        self.is_restful = False
        self.is_https = False
        self.is_local = False
        self.global_settings = settings.global_settings
        self._uuid = None

    def parse_get_vars(self):
        """Takes the QUERY_STRING and unpacks it to get_vars
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -186,7 +186,6 @@
         Storage.__init__(self)
         self.env = Storage(env)
         self.env.web2py_path = global_settings.applications_parent
-        self.env.update(global_settings)
         self.cookies = Cookie.SimpleCookie()
         self._get_vars = None
         self._post_vars = None
@@ -202,7 +201,6 @@
         self.is_restful = False
         self.is_https = False
         self.is_local = False
-        self.global_settings = settings.global_settings
         self._uuid = None
 
     def parse_get_vars(self):
```
