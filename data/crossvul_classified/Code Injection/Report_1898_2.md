# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in java
**Pair ID:** 1898_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1898_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```java
Lines 1-9 of the vulnerable file.

package io.onedev.server.product;

public class Test {

	@org.junit.Test
	public void test() {
	}		
	
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,5 +5,5 @@
 	@org.junit.Test
 	public void test() {
 	}		
-	
+
 }
```
