# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in java
**Pair ID:** 2031_4
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2031_4`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```java
Lines 82-123 of the vulnerable file.

            throw new SecurityException("Cannot parse policy file: " + exp,exp);
        }
    }

    /** {@inheritDoc} */
    public boolean isHttpMethodAllowed(HttpMethod method) {
        return httpChecker.check(method);
    }

    /** {@inheritDoc} */
    public boolean isTypeAllowed(RequestType pType) {
        return requestTypeChecker.check(pType);
    }

    /** {@inheritDoc} */
    public boolean isRemoteAccessAllowed(String ... pHostOrAddress) {
        return networkChecker.check(pHostOrAddress);
    }

    /** {@inheritDoc} */
    public boolean isCorsAccessAllowed(String pOrigin) {
        return corsChecker.check(pOrigin);
    }

    /** {@inheritDoc} */
    public boolean isAttributeReadAllowed(ObjectName pName, String pAttribute) {
        return check(RequestType.READ,pName,pAttribute);
    }

    /** {@inheritDoc} */
    public boolean isAttributeWriteAllowed(ObjectName pName, String pAttribute) {
        return check(RequestType.WRITE,pName, pAttribute);
    }

    /** {@inheritDoc} */
    public boolean isOperationAllowed(ObjectName pName, String pOperation) {
        return check(RequestType.EXEC,pName, pOperation);
    }

    /** {@inheritDoc} */
    private boolean check(RequestType pType, ObjectName pName, String pValue) {
        return mbeanAccessChecker.check(new MBeanAccessChecker.Arg(isTypeAllowed(pType), pType, pName, pValue));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -99,8 +99,8 @@
     }
 
     /** {@inheritDoc} */
-    public boolean isCorsAccessAllowed(String pOrigin) {
-        return corsChecker.check(pOrigin);
+    public boolean isOriginAllowed(String pOrigin, boolean pIsStrictCheck) {
+        return corsChecker.check(pOrigin,pIsStrictCheck);
     }
 
     /** {@inheritDoc} */
```
