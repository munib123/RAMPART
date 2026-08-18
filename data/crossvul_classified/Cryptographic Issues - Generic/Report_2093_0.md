# CrossVul Fix Pair: Cryptographic Issues in java
**Pair ID:** 2093_0
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2093_0`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```java
Lines 1447-1487 of the vulnerable file.

    public List<String> getLoggerNames() {
        while (true) {
            try {
                List<String> r = new ArrayList<String>();
                Enumeration<String> e = LogManager.getLogManager().getLoggerNames();
                while (e.hasMoreElements())
                    r.add(e.nextElement());
                return r;
            } catch (ConcurrentModificationException e) {
                // retry
            }
        }
    }

    /**
     * Used by &lt;f:password/> so that we send an encrypted value to the client.
     */
    public String getPasswordValue(Object o) {
        if (o==null)    return null;
        if (o instanceof Secret)    return ((Secret)o).getEncryptedValue();
        return o.toString();
    }

    public List filterDescriptors(Object context, Iterable descriptors) {
        return DescriptorVisibilityFilter.apply(context,descriptors);
    }
    
    /**
     * Returns true if we are running unit tests.
     */
    public static boolean getIsUnitTest() {
        return Main.isUnitTest;
    }

    /**
     * Returns {@code true} if the {@link Run#ARTIFACTS} permission is enabled,
     * {@code false} otherwise.
     *
     * <p>When the {@link Run#ARTIFACTS} permission is not turned on using the
     * {@code hudson.security.ArtifactsPermission} system property, this
     * permission must not be considered to be set to {@code false} for every
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1464,6 +1464,9 @@
     public String getPasswordValue(Object o) {
         if (o==null)    return null;
         if (o instanceof Secret)    return ((Secret)o).getEncryptedValue();
+        if (getIsUnitTest()) {
+            throw new SecurityException("attempted to render plaintext ‘" + o + "’ in password field; use a getter of type Secret instead");
+        }
         return o.toString();
     }
 
```
