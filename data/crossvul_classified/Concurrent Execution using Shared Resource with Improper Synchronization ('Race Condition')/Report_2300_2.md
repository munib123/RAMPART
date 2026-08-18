# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in java
**Pair ID:** 2300_2
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2300_2`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```java
Lines 6-46 of the vulnerable file.

 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jboss.weld.servlet;

import javax.servlet.ServletContext;
import javax.servlet.ServletRequestListener;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.jboss.weld.Container;
import org.jboss.weld.bootstrap.api.Service;
import org.jboss.weld.context.cache.RequestScopedCache;
import org.jboss.weld.context.http.HttpRequestContext;
import org.jboss.weld.context.http.HttpRequestContextImpl;
import org.jboss.weld.context.http.HttpSessionContext;
import org.jboss.weld.context.http.HttpSessionDestructionContext;
import org.jboss.weld.event.FastEvent;
import org.jboss.weld.literal.DestroyedLiteral;
import org.jboss.weld.literal.InitializedLiteral;
import org.jboss.weld.logging.ServletLogger;
import org.jboss.weld.manager.BeanManagerImpl;
import org.jboss.weld.servlet.spi.HttpContextActivationFilter;
import org.jboss.weld.util.reflection.Reflections;

/**
 * Takes care of setting up and tearing down CDI contexts around an HTTP request and dispatching context lifecycle events.
 *
 * @author Jozef Hartinger
 * @author Marko Luksa
 *
 */
public class HttpContextLifecycle implements Service {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,6 +23,8 @@
 
 import org.jboss.weld.Container;
 import org.jboss.weld.bootstrap.api.Service;
+import org.jboss.weld.context.BoundContext;
+import org.jboss.weld.context.ManagedContext;
 import org.jboss.weld.context.cache.RequestScopedCache;
 import org.jboss.weld.context.http.HttpRequestContext;
 import org.jboss.weld.context.http.HttpRequestContextImpl;
@@ -279,24 +281,21 @@
             if (!servletApi.isAsyncSupported() || !servletApi.isAsyncStarted(request)) {
                 getRequestContext().invalidate();
             }
-            getRequestContext().deactivate();
+
+            safelyDeactivate(getRequestContext(),  request);
             // fire @Destroyed(RequestScoped.class)
             requestDestroyedEvent.fire(request);
-            getSessionContext().deactivate();
+
+            safelyDeactivate(getSessionContext(), request);
             // fire @Destroyed(SessionScoped.class)
             if (!getSessionContext().isValid()) {
                 sessionDestroyedEvent.fire((HttpSession) request.getAttribute(HTTP_SESSION));
             }
         } finally {
-            getRequestContext().dissociate(request);
-
+            safelyDissociate(getRequestContext(), request);
             // WFLY-1533 Underlying HTTP session may be invalid
-            try {
-                getSessionContext().dissociate(request);
-            } catch (Exception e) {
-                ServletLogger.LOG.unableToDissociateContext(getSessionContext(), request);
-                ServletLogger.LOG.catchingDebug(e);
-            }
+            safelyDissociate(getSessionContext(), request);
+
             // Catch block is inside the activator method so that we're able to log the context
             conversationContextActivator.disassociateConversationContext(request);
 
@@ -310,6 +309,10 @@
 
     public void setConversationActivationEnabled(boolean conversationActivationEnabled) {
         this.conversationActivationEnabled = conversationActivationEnabled;
+    }
+
+    @Override
+    public void cleanup() {
     }
 
     /**
@@ -338,7 +341,22 @@
         return request.getAttribute(REQUEST_DESTROYED) != null;
     }
 
-    @Override
-    public void cleanup() {
-    }
+    private <T> void safelyDissociate(BoundContext<T> context, T storage) {
+        try {
+            context.dissociate(storage);
+        } catch(Exception e) {
+            ServletLogger.LOG.unableToDissociateContext(context, storage);
+            ServletLogger.LOG.catchingDebug(e);
+        }
+    }
+
+    private void safelyDeactivate(ManagedContext context, HttpServletRequest request) {
+        try {
+            context.deactivate();
+        } catch(Exception e) {
+            ServletLogger.LOG.unableToDeactivateContext(context, request);
+            ServletLogger.LOG.catchingDebug(e);
+        }
+    }
+
 }
```
