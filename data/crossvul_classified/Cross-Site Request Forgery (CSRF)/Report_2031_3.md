# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in java
**Pair ID:** 2031_3
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2031_3`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```java
Lines 56-79 of the vulnerable file.

    public final boolean isAttributeReadAllowed(ObjectName pName, String pAttribute) {
        return isAllowed;
    }

    /** {@inheritDoc} */
    public final boolean isAttributeWriteAllowed(ObjectName pName, String pAttribute) {
        return isAllowed;
    }

    /** {@inheritDoc} */
    public final boolean isOperationAllowed(ObjectName pName, String pOperation) {
        return isAllowed;
    }

    /** {@inheritDoc} */
    public final boolean isRemoteAccessAllowed(String... pHostOrAddress) {
        return isAllowed;
    }

    /** {@inheritDoc} */
    public boolean isCorsAccessAllowed(String pOrigin) {
        return isAllowed;
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -73,7 +73,7 @@
     }
 
     /** {@inheritDoc} */
-    public boolean isCorsAccessAllowed(String pOrigin) {
+    public boolean isOriginAllowed(String pOrigin, boolean pIsStrictCheck) {
         return isAllowed;
     }
 }
```
