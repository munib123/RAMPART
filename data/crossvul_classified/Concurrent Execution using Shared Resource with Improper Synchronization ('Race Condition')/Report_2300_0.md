# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in java
**Pair ID:** 2300_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2300_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```java
Lines 1-42 of the vulnerable file.

/*
 * JBoss, Home of Professional Open Source
 * Copyright 2013, Red Hat, Inc., and individual contributors
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
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
package org.jboss.weld.logging;

import static org.jboss.weld.logging.WeldLogger.WELD_PROJECT_CODE;

import javax.enterprise.context.spi.Context;
import javax.servlet.http.HttpServletRequest;

import org.jboss.logging.Logger;
import org.jboss.logging.Logger.Level;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.Message.Format;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.weld.exceptions.IllegalStateException;
import org.jboss.weld.servlet.ServletContextService;

/**
 * Error messages relating to Servlet integration
 *
 * Message ids: 000700 - 000799
 */
@MessageLogger(projectCode = WELD_PROJECT_CODE)
public interface ServletLogger extends WeldLogger {

    ServletLogger LOG = Logger.getMessageLogger(ServletLogger.class, Category.SERVLET.getName());
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,9 +17,6 @@
 package org.jboss.weld.logging;
 
 import static org.jboss.weld.logging.WeldLogger.WELD_PROJECT_CODE;
-
-import javax.enterprise.context.spi.Context;
-import javax.servlet.http.HttpServletRequest;
 
 import org.jboss.logging.Logger;
 import org.jboss.logging.Logger.Level;
@@ -60,8 +57,8 @@
     void webXmlMappingPatternIgnored(String pattern);
 
     @LogMessage(level = Level.WARN)
-    @Message(id = 712, value = "Unable to dissociate context {0} when destroying request {1}", format = Format.MESSAGE_FORMAT)
-    void unableToDissociateContext(Context context, HttpServletRequest request);
+    @Message(id = 712, value = "Unable to dissociate context {0} from the storage {1}", format = Format.MESSAGE_FORMAT)
+    void unableToDissociateContext(Object context, Object storage);
 
     @Message(id = 713, value = "Unable to inject ServletContext. None is associated with {0}, {1}", format = Format.MESSAGE_FORMAT)
     IllegalStateException cannotInjectServletContext(ClassLoader classLoader, ServletContextService service);
@@ -78,4 +75,8 @@
     @Message(id = 716, value = "Running in Servlet 2.x environment. Asynchronous request support is disabled.")
     void servlet2Environment();
 
+    @LogMessage(level = Level.WARN)
+    @Message(id = 717, value = "Unable to deactivate context {0} when destroying request {1}", format = Format.MESSAGE_FORMAT)
+    void unableToDeactivateContext(Object context, Object request);
+
 }
```
