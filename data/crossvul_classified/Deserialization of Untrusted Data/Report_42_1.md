# CrossVul Fix Pair: Deserialization of Untrusted Data in java
**Pair ID:** 42_1
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `42_1`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```java
Lines 27-74 of the vulnerable file.

    private int[] vi;// set of vinegar vars per layer.

    /**
     * Default Constructor The elements of the array containing the number of
     * Vinegar variables in each layer are set to the default values here.
     */
    public RainbowParameters()
    {
        this.vi = this.DEFAULT_VI;
    }

    /**
     * Constructor with parameters
     *
     * @param vi The elements of the array containing the number of Vinegar
     *           variables per layer are set to the values of the input array.
     */
    public RainbowParameters(int[] vi)
    {
        this.vi = vi;
        try
        {
            checkParams();
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    private void checkParams()
        throws Exception
    {
        if (vi == null)
        {
            throw new Exception("no layers defined.");
        }
        if (vi.length > 1)
        {
            for (int i = 0; i < vi.length - 1; i++)
            {
                if (vi[i] >= vi[i + 1])
                {
                    throw new Exception(
                        "v[i] has to be smaller than v[i+1]");
                }
            }
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -44,22 +44,15 @@
     public RainbowParameters(int[] vi)
     {
         this.vi = vi;
-        try
-        {
-            checkParams();
-        }
-        catch (Exception e)
-        {
-            e.printStackTrace();
-        }
+
+        checkParams();
     }
 
     private void checkParams()
-        throws Exception
     {
         if (vi == null)
         {
-            throw new Exception("no layers defined.");
+            throw new IllegalArgumentException("no layers defined.");
         }
         if (vi.length > 1)
         {
@@ -67,14 +60,14 @@
             {
                 if (vi[i] >= vi[i + 1])
                 {
-                    throw new Exception(
+                    throw new IllegalArgumentException(
                         "v[i] has to be smaller than v[i+1]");
                 }
             }
         }
         else
         {
-            throw new Exception(
+            throw new IllegalArgumentException(
                 "Rainbow needs at least 1 layer, such that v1 < v2.");
         }
     }
```
