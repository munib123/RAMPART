# CrossVul Fix Pair: Improper Input Validation in java
**Pair ID:** 761_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `761_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```java
Lines 1-41 of the vulnerable file.

/**
 * Copyright (c) 2001-2019 Mathew A. Nelson and Robocode contributors
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * https://robocode.sourceforge.io/license/epl-v10.html
 */
package net.sf.robocode.test.robots;


import net.sf.robocode.test.helpers.RobocodeTestBed;
import org.junit.Assert;
import robocode.control.events.TurnEndedEvent;


/**
 * @author Flemming N. Larsen (original)
 */
public class TestHttpAttack extends RobocodeTestBed {

	private boolean messagedAccessDenied;
	
	@Override
	public String getRobotNames() {
		return "tested.robots.HttpAttack,sample.Target";
	}

	@Override
	public void onTurnEnded(TurnEndedEvent event) {
		super.onTurnEnded(event);

		final String out = event.getTurnSnapshot().getRobots()[0].getOutputStreamSnapshot();

		if (out.contains("access denied (java.net.SocketPermission")
				|| out.contains("access denied (\"java.net.SocketPermission\"")) {
			messagedAccessDenied = true;	
		}	
	}

	@Override
	protected void runTeardown() {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,7 +18,7 @@
  */
 public class TestHttpAttack extends RobocodeTestBed {
 
-	private boolean messagedAccessDenied;
+	private boolean securityExceptionOccurred;
 	
 	@Override
 	public String getRobotNames() {
@@ -31,19 +31,18 @@
 
 		final String out = event.getTurnSnapshot().getRobots()[0].getOutputStreamSnapshot();
 
-		if (out.contains("access denied (java.net.SocketPermission")
-				|| out.contains("access denied (\"java.net.SocketPermission\"")) {
-			messagedAccessDenied = true;	
+		if (out.contains("java.lang.SecurityException:")) {
+			securityExceptionOccurred = true;	
 		}	
 	}
 
 	@Override
 	protected void runTeardown() {
-		Assert.assertTrue("HTTP connection is not allowed", messagedAccessDenied);
+		Assert.assertTrue("Socket connection is not allowed", securityExceptionOccurred);
 	}
 
 	@Override
 	protected int getExpectedErrors() {
-		return hasJavaNetURLPermission ? 2 : 1; // Security error must be reported as an error. Java 8 reports two errors.
+		return 1;
 	}
 }
```
