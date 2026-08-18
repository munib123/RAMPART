# CrossVul Fix Pair: Deserialization of Untrusted Data in java
**Pair ID:** 42_4
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `42_4`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```java
Lines 304-344 of the vulnerable file.

    public static long getTreeIndex(long index, int xmssTreeHeight)
    {
        return index >> xmssTreeHeight;
    }

    public static int getLeafIndex(long index, int xmssTreeHeight)
    {
        return (int)(index & ((1L << xmssTreeHeight) - 1L));
    }

    public static byte[] serialize(Object obj)
        throws IOException
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(out);
        oos.writeObject(obj);
        oos.flush();
        return out.toByteArray();
    }

    public static Object deserialize(byte[] data)
        throws IOException, ClassNotFoundException
    {
        ByteArrayInputStream in = new ByteArrayInputStream(data);
        ObjectInputStream is = new ObjectInputStream(in);
        return is.readObject();
    }

    public static int calculateTau(int index, int height)
    {
        int tau = 0;
        for (int i = 0; i < height; i++)
        {
            if (((index >> i) & 1) == 0)
            {
                tau = i;
                break;
            }
        }
        return tau;
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -321,12 +321,25 @@
         return out.toByteArray();
     }
 
-    public static Object deserialize(byte[] data)
+    public static Object deserialize(byte[] data, Class clazz)
         throws IOException, ClassNotFoundException
     {
         ByteArrayInputStream in = new ByteArrayInputStream(data);
         ObjectInputStream is = new ObjectInputStream(in);
-        return is.readObject();
+        Object obj = is.readObject();
+
+        if (is.available() != 0)
+        {
+            throw new IOException("unexpected data found at end of ObjectInputStream");
+        }
+        if (clazz.isInstance(obj))
+        {
+            return obj;
+        }
+        else
+        {
+            throw new IOException("unexpected class found in ObjectInputStream");
+        }
     }
 
     public static int calculateTau(int index, int height)
```
