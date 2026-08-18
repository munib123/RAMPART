# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in java
**Pair ID:** 2299_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2299_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```java
Lines 54-94 of the vulnerable file.

            cache.add(item);
            return true;
        }
        return false;
    }

    public static boolean addItemIfActive(final ThreadLocal<?> item) {
        final List<RequestScopedItem> cache = CACHE.get();
        if (cache != null) {
            cache.add(new RequestScopedItem() {
                public void invalidate() {
                    item.remove();
                }
            });
            return true;
        }
        return false;
    }

    public static void beginRequest() {
        CACHE.set(new LinkedList<RequestScopedItem>());
    }

    /**
     * ends the request and clears the cache. This can be called before the request is over,
     * in which case the cache will be unavailable for the rest of the request.
     */
    public static void endRequest() {
        final List<RequestScopedItem> result = CACHE.get();
        CACHE.remove();
        if (result != null) {
            for (final RequestScopedItem item : result) {
                item.invalidate();
            }
        }
    }

    /**
     * Flushes the bean cache. The cache remains available for the rest of the request.
     */
    public static void invalidate() {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -71,6 +71,8 @@
     }
 
     public static void beginRequest() {
+        // if the previous request was not ended properly for some reason, make sure it is ended now
+        endRequest();
         CACHE.set(new LinkedList<RequestScopedItem>());
     }
 
@@ -80,8 +82,8 @@
      */
     public static void endRequest() {
         final List<RequestScopedItem> result = CACHE.get();
-        CACHE.remove();
         if (result != null) {
+            CACHE.remove();
             for (final RequestScopedItem item : result) {
                 item.invalidate();
             }
```
