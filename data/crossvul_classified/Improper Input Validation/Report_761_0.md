# CrossVul Fix Pair: Improper Input Validation in java
**Pair ID:** 761_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `761_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```java
Lines 1-35 of the vulnerable file.

/**
 * Copyright (c) 2001-2019 Mathew A. Nelson and Robocode contributors
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * https://robocode.sourceforge.io/license/epl-v10.html
 */
package net.sf.robocode.host.security;


import net.sf.robocode.host.IHostedThread;
import net.sf.robocode.host.IThreadManager;
import net.sf.robocode.io.RobocodeProperties;

import java.security.AccessControlException;


/**
 * @author Mathew A. Nelson (original)
 * @author Flemming N. Larsen (contributor)
 * @author Robert D. Maupin (contributor)
 * @author Pavel Savara (contributor)
 */
public class RobocodeSecurityManager extends SecurityManager {

	private final IThreadManager threadManager;

	public RobocodeSecurityManager(IThreadManager threadManager) {
		super();
		this.threadManager = threadManager;

		ThreadGroup tg = Thread.currentThread().getThreadGroup();

		while (tg != null) {
			threadManager.addSafeThreadGroup(tg);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,7 +12,9 @@
 import net.sf.robocode.host.IThreadManager;
 import net.sf.robocode.io.RobocodeProperties;
 
+import java.net.SocketPermission;
 import java.security.AccessControlException;
+import java.security.Permission;
 
 
 /**
@@ -49,7 +51,6 @@
 		}
 
 		Thread c = Thread.currentThread();
-
 		if (isSafeThread(c)) {
 			return;
 		}
@@ -84,7 +85,7 @@
 			if (robotProxy != null) {
 				robotProxy.punishSecurityViolation(message);
 			}
-			throw new AccessControlException(message);
+			throw new SecurityException(message);
 		}
 	}
 
@@ -94,7 +95,6 @@
 			return;
 		}
 		Thread c = Thread.currentThread();
-
 		if (isSafeThread(c)) {
 			return;
 		}
@@ -123,9 +123,27 @@
 			String message = "Robots are only allowed to create up to 5 threads!";
 
 			robotProxy.punishSecurityViolation(message);
-			throw new AccessControlException(message);
+			throw new SecurityException(message);
 		}
 	}
+	
+    public void checkPermission(Permission perm) {
+		if (RobocodeProperties.isSecurityOff()) {
+			return;
+		}
+		Thread c = Thread.currentThread();
+		if (isSafeThread(c)) {
+			return;
+		}
+        super.checkPermission(perm);
+
+        if (perm instanceof SocketPermission) {
+    		IHostedThread robotProxy = threadManager.getLoadedOrLoadingRobotProxy(c);
+        	String message = "Using socket is not allowed";
+        	robotProxy.punishSecurityViolation(message);
+            throw new SecurityException(message);
+        }
+    }
 
 	private boolean isSafeThread(Thread c) {
 		return threadManager.isSafeThread(c);
```
