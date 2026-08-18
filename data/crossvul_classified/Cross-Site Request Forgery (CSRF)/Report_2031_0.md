# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in java
**Pair ID:** 2031_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2031_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```java
Lines 206-246 of the vulnerable file.

        } catch (JMException e) {
            error("Cannot unregister MBean: " + e,e);
        }
    }

    /**
     * Check whether remote access from the given client is allowed.
     *
     * @param pRemoteHost remote host to check against
     * @param pRemoteAddr alternative IP address
     * @return true if remote access is allowed
     */
    public boolean isRemoteAccessAllowed(String pRemoteHost, String pRemoteAddr) {
        return restrictor.isRemoteAccessAllowed(pRemoteHost, pRemoteAddr);
    }

    /**
     * Check whether CORS access is allowed for the given origin.
     *
     * @param pOrigin origin URL which needs to be checked
     * @return true if icors access is allowed
     */
    public boolean isCorsAccessAllowed(String pOrigin) {
        return restrictor.isCorsAccessAllowed(pOrigin);
    }

    /**
     * Log at info level
     *
     * @param msg to log
     */
    public void info(String msg) {
        logHandler.info(msg);
        if (debugStore != null) {
            debugStore.log(msg);
        }
    }

    /**
     * Log at debug level
     *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -223,10 +223,11 @@
      * Check whether CORS access is allowed for the given origin.
      *
      * @param pOrigin origin URL which needs to be checked
-     * @return true if icors access is allowed
-     */
-    public boolean isCorsAccessAllowed(String pOrigin) {
-        return restrictor.isCorsAccessAllowed(pOrigin);
+     * @param pStrictChecking whether to a strict check (i.e. server side check)
+     * @return true if if cors access is allowed
+     */
+    public boolean isOriginAllowed(String pOrigin,boolean pStrictChecking) {
+        return restrictor.isOriginAllowed(pOrigin, pStrictChecking);
     }
 
     /**
```
