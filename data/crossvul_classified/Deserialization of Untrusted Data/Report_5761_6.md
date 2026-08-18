# CrossVul Fix Pair: Deserialization of Untrusted Data in java
**Pair ID:** 5761_6
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5761_6`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```java
Lines 1-23 of the vulnerable file.

package org.richfaces.demo.paint2d;

import java.io.Serializable;

public class PaintData implements Serializable{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	String text;
	Integer color;
	float scale;


	public Integer getColor() {
		return color;
	}
	public void setColor(Integer color) {
		this.color = color;
	}
	public float getScale() {
		return scale;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,8 +1,8 @@
 package org.richfaces.demo.paint2d;
 
-import java.io.Serializable;
+import org.ajax4jsf.resource.SerializableResource;
 
-public class PaintData implements Serializable{
+public class PaintData implements SerializableResource {
 	/**
 	 * 
 	 */
```
