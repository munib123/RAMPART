# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in java
**Pair ID:** 2300_1
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2300_1`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```java
Lines 121-169 of the vulnerable file.

        }
    }

    protected void associateConversationContext(HttpServletRequest request) {
        httpConversationContext().associate(request);
    }

    private void setContextActivatedInRequest(HttpServletRequest request) {
        request.setAttribute(CONTEXT_ACTIVATED_IN_REQUEST, true);
    }

    private boolean isContextActivatedInRequest(HttpServletRequest request) {
        Object result = request.getAttribute(CONTEXT_ACTIVATED_IN_REQUEST);
        if (result == null) {
            return false;
        }
        return (Boolean) result;
    }

    protected void deactivateConversationContext(HttpServletRequest request) {
        ConversationContext conversationContext = httpConversationContext();
        if (conversationContext.isActive()) {
            // Only deactivate the context if one is already active, otherwise we get Exceptions
            if (conversationContext instanceof LazyHttpConversationContextImpl) {
                LazyHttpConversationContextImpl lazyConversationContext = (LazyHttpConversationContextImpl) conversationContext;
                if (!lazyConversationContext.isInitialized()) {
                    // if this lazy conversation has not been touched yet, just deactivate it
                    lazyConversationContext.deactivate();
                    return;
                }
            }
            boolean isTransient = conversationContext.getCurrentConversation().isTransient();
            if (ConversationLogger.LOG.isTraceEnabled()) {
                if (isTransient) {
                    ConversationLogger.LOG.cleaningUpTransientConversation();
                } else {
                    ConversationLogger.LOG.cleaningUpConversation(conversationContext.getCurrentConversation().getId());
                }
            }
            conversationContext.invalidate();
            conversationContext.deactivate();
            if (isTransient) {
                conversationDestroyedEvent.fire(request);
            }
        }
    }

    protected void disassociateConversationContext(HttpServletRequest request) {
        try {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -138,30 +138,35 @@
     }
 
     protected void deactivateConversationContext(HttpServletRequest request) {
-        ConversationContext conversationContext = httpConversationContext();
-        if (conversationContext.isActive()) {
-            // Only deactivate the context if one is already active, otherwise we get Exceptions
-            if (conversationContext instanceof LazyHttpConversationContextImpl) {
-                LazyHttpConversationContextImpl lazyConversationContext = (LazyHttpConversationContextImpl) conversationContext;
-                if (!lazyConversationContext.isInitialized()) {
-                    // if this lazy conversation has not been touched yet, just deactivate it
-                    lazyConversationContext.deactivate();
-                    return;
+        try {
+            ConversationContext conversationContext = httpConversationContext();
+            if (conversationContext.isActive()) {
+                // Only deactivate the context if one is already active, otherwise we get Exceptions
+                if (conversationContext instanceof LazyHttpConversationContextImpl) {
+                    LazyHttpConversationContextImpl lazyConversationContext = (LazyHttpConversationContextImpl) conversationContext;
+                    if (!lazyConversationContext.isInitialized()) {
+                        // if this lazy conversation has not been touched yet, just deactivate it
+                        lazyConversationContext.deactivate();
+                        return;
+                    }
+                }
+                boolean isTransient = conversationContext.getCurrentConversation().isTransient();
+                if (ConversationLogger.LOG.isTraceEnabled()) {
+                    if (isTransient) {
+                        ConversationLogger.LOG.cleaningUpTransientConversation();
+                    } else {
+                        ConversationLogger.LOG.cleaningUpConversation(conversationContext.getCurrentConversation().getId());
+                    }
+                }
+                conversationContext.invalidate();
+                conversationContext.deactivate();
+                if (isTransient) {
+                    conversationDestroyedEvent.fire(request);
                 }
             }
-            boolean isTransient = conversationContext.getCurrentConversation().isTransient();
-            if (ConversationLogger.LOG.isTraceEnabled()) {
-                if (isTransient) {
-                    ConversationLogger.LOG.cleaningUpTransientConversation();
-                } else {
-                    ConversationLogger.LOG.cleaningUpConversation(conversationContext.getCurrentConversation().getId());
-                }
-            }
-            conversationContext.invalidate();
-            conversationContext.deactivate();
-            if (isTransient) {
-                conversationDestroyedEvent.fire(request);
-            }
+        } catch (Exception e) {
+            ServletLogger.LOG.unableToDeactivateContext(httpConversationContext(), request);
+            ServletLogger.LOG.catchingDebug(e);
         }
     }
 
```
