# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 2141_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2141_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 26-59 of the vulnerable file.

        comm_ok=True, diff=dict()):

        # which host is this ReturnData about?
        if conn is not None:
            self.host = conn.host
            delegate = getattr(conn, 'delegate', None)
            if delegate is not None:
                self.host = delegate

        else:
            self.host = host

        self.result = result
        self.comm_ok = comm_ok

        # if these values are set and used with --diff we can show
        # changes made to particular files
        self.diff = diff

        if type(self.result) in [ str, unicode ]:
            self.result = utils.parse_json(self.result)


        if self.host is None:
            raise Exception("host not set")
        if type(self.result) != dict:
            raise Exception("dictionary result expected")

    def communicated_ok(self):
        return self.comm_ok

    def is_successful(self):
        return self.comm_ok and (self.result.get('failed', False) == False) and ('failed_when_result' in self.result and [not self.result['failed_when_result']] or [self.result.get('rc',0) == 0])[0]

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,8 +43,7 @@
         self.diff = diff
 
         if type(self.result) in [ str, unicode ]:
-            self.result = utils.parse_json(self.result)
-
+            self.result = utils.parse_json(self.result, from_remote=True)
 
         if self.host is None:
             raise Exception("host not set")
```
