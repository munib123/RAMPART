# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in java
**Pair ID:** 3048_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3048_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```java
Lines 1055-1096 of the vulnerable file.


    public String getSearchUrl() {
        return getUrl();
    }

    /**
     * {@link RetentionStrategy} associated with this computer.
     *
     * @return
     *      never null. This method return {@code RetentionStrategy<? super T>} where
     *      {@code T=this.getClass()}.
     */
    public abstract RetentionStrategy getRetentionStrategy();

    /**
     * Expose monitoring data for the remote API.
     */
    @Exported(inline=true)
    public Map<String/*monitor name*/,Object> getMonitorData() {
        Map<String,Object> r = new HashMap<String, Object>();
        for (NodeMonitor monitor : NodeMonitor.getAll())
            r.put(monitor.getClass().getName(),monitor.data(this));
        return r;
    }

    /**
     * Gets the system properties of the JVM on this computer.
     * If this is the master, it returns the system property of the master computer.
     */
    public Map<Object,Object> getSystemProperties() throws IOException, InterruptedException {
        return RemotingDiagnostics.getSystemProperties(getChannel());
    }

    /**
     * @deprecated as of 1.292
     *      Use {@link #getEnvironment()} instead.
     */
    @Deprecated
    public Map<String,String> getEnvVars() throws IOException, InterruptedException {
        return getEnvironment();
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1072,8 +1072,10 @@
     @Exported(inline=true)
     public Map<String/*monitor name*/,Object> getMonitorData() {
         Map<String,Object> r = new HashMap<String, Object>();
-        for (NodeMonitor monitor : NodeMonitor.getAll())
-            r.put(monitor.getClass().getName(),monitor.data(this));
+        if (hasPermission(CONNECT)) {
+            for (NodeMonitor monitor : NodeMonitor.getAll())
+                r.put(monitor.getClass().getName(), monitor.data(this));
+        }
         return r;
     }
 
```
