# CrossVul Fix Pair: Deserialization of Untrusted Data in java
**Pair ID:** 42_0
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `42_0`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```java
Lines 161-202 of the vulnerable file.

        byte[][] nextRoots = new byte[numLayer - 1][mdLength];
        // initialize seeds
        byte[][] seeds = new byte[numLayer][mdLength];
        // initialize seeds[] by copying starting-seeds of first trees of each
        // layer
        for (int i = 0; i < numLayer; i++)
        {
            System.arraycopy(currentSeeds[i], 0, seeds[i], 0, mdLength);
        }

        // initialize rootSigs
        currentRootSigs = new byte[numLayer - 1][mdLength];

        // -------------------------
        // -------------------------
        // --- calculation of current authpaths and current rootsigs (AUTHPATHS,
        // SIG)------
        // from bottom up to the root
        for (int h = numLayer - 1; h >= 0; h--)
        {
            GMSSRootCalc tree = new GMSSRootCalc(this.heightOfTrees[h], this.K[h], digestProvider);
            try
            {
                // on lowest layer no lower root is available, so just call
                // the method with null as first parameter
                if (h == numLayer - 1)
                {
                    tree = this.generateCurrentAuthpathAndRoot(null, currentStack[h], seeds[h], h);
                }
                else
                // otherwise call the method with the former computed root
                // value
                {
                    tree = this.generateCurrentAuthpathAndRoot(currentRoots[h + 1], currentStack[h], seeds[h], h);
                }

            }
            catch (Exception e1)
            {
                e1.printStackTrace();
            }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -178,26 +178,19 @@
         // from bottom up to the root
         for (int h = numLayer - 1; h >= 0; h--)
         {
-            GMSSRootCalc tree = new GMSSRootCalc(this.heightOfTrees[h], this.K[h], digestProvider);
-            try
-            {
-                // on lowest layer no lower root is available, so just call
-                // the method with null as first parameter
-                if (h == numLayer - 1)
-                {
-                    tree = this.generateCurrentAuthpathAndRoot(null, currentStack[h], seeds[h], h);
-                }
-                else
-                // otherwise call the method with the former computed root
-                // value
-                {
-                    tree = this.generateCurrentAuthpathAndRoot(currentRoots[h + 1], currentStack[h], seeds[h], h);
-                }
-
-            }
-            catch (Exception e1)
-            {
-                e1.printStackTrace();
+            GMSSRootCalc tree;
+
+            // on lowest layer no lower root is available, so just call
+            // the method with null as first parameter
+            if (h == numLayer - 1)
+            {
+                tree = this.generateCurrentAuthpathAndRoot(null, currentStack[h], seeds[h], h);
+            }
+            else
+            // otherwise call the method with the former computed root
+            // value
+            {
+                tree = this.generateCurrentAuthpathAndRoot(currentRoots[h + 1], currentStack[h], seeds[h], h);
             }
 
             // set initial values needed for the private key construction
```
