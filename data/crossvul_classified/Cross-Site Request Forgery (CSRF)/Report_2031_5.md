# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in java
**Pair ID:** 2031_5
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2031_5`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```java
Lines 73-97 of the vulnerable file.

     * @param pName MBean name
     * @param pOperation attribute to check
     * @return true if access is allowed
     */
    boolean isOperationAllowed(ObjectName pName,String pOperation);

    /**
     * Check whether access from the connected client is allowed. If at least
     * one of the given parameters matches, then this method returns true.
     *
     * @return true is access is allowed
     * @param pHostOrAddress one or more host or address names
     */
    boolean isRemoteAccessAllowed(String ... pHostOrAddress);

    /**
     * Check whether cross browser access via CORS is allowed. See the
     * <a href="https://developer.mozilla.org/en/http_access_control">CORS</a> specification
     * for details
     *
     * @param pOrigin the "Origin:" URL provided within the request
     * @return true if this cross browser request allowed, false otherwise
     */
    boolean isCorsAccessAllowed(String pOrigin);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -90,8 +90,9 @@
      * <a href="https://developer.mozilla.org/en/http_access_control">CORS</a> specification
      * for details
      *
-     * @param pOrigin the "Origin:" URL provided within the request
+     * @param pOrigin the "Origin:" header provided within the request
+     * @param pIsStrictCheck whether doing a strict check
      * @return true if this cross browser request allowed, false otherwise
      */
-    boolean isCorsAccessAllowed(String pOrigin);
+    boolean isOriginAllowed(String pOrigin, boolean pIsStrictCheck);
 }
```
