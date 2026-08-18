# CrossVul Fix Pair: Deserialization of Untrusted Data in java
**Pair ID:** 5761_5
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5761_5`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```java
Lines 1-24 of the vulnerable file.

package org.richfaces.demo.media;

import java.awt.Color;
import java.io.Serializable;

public class MediaData implements Serializable{

	private static final long serialVersionUID = 1L;
	Integer Width=110;
	Integer Height=50;
	Color Background=new Color(0,0,0);
	Color DrawColor=new Color(255,255,255);
	public MediaData() {
	}
	public Color getBackground() {
		return Background;
	}
	public void setBackground(Color background) {
		Background = background;
	}
	public Color getDrawColor() {
		return DrawColor;
	}
	public void setDrawColor(Color drawColor) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,9 +1,10 @@
 package org.richfaces.demo.media;
 
 import java.awt.Color;
-import java.io.Serializable;
 
-public class MediaData implements Serializable{
+import org.ajax4jsf.resource.SerializableResource;
+
+public class MediaData implements SerializableResource {
 
 	private static final long serialVersionUID = 1L;
 	Integer Width=110;
```
