# CrossVul Fix Pair: Improper Authentication in java
**Pair ID:** 3052_7
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3052_7`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```java
Lines 1-31 of the vulnerable file.

package jenkins.security.s2m;

import hudson.Extension;
import hudson.FilePath;
import hudson.model.AdministrativeMonitor;
import hudson.remoting.Callable;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.QueryParameter;

import javax.inject.Inject;
import java.io.IOException;

/**
 * Report any rejected {@link Callable}s and {@link FilePath} executions and allow
 * admins to whitelist them.
 *
 * @since 1.THU
 * @author Kohsuke Kawaguchi
 */
@Extension
public class AdminCallableMonitor extends AdministrativeMonitor {
    @Inject
    Jenkins jenkins;

    @Inject
    AdminWhitelistRule rule;

    public AdminCallableMonitor() {
        super("slaveToMasterAccessControl");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,6 +8,7 @@
 import org.kohsuke.stapler.HttpResponse;
 import org.kohsuke.stapler.HttpResponses;
 import org.kohsuke.stapler.QueryParameter;
+import org.kohsuke.stapler.interceptor.RequirePOST;
 
 import javax.inject.Inject;
 import java.io.IOException;
@@ -49,6 +50,7 @@
     /**
      * Depending on whether the user said "examin" or "dismiss", send him to the right place.
      */
+    @RequirePOST
     public HttpResponse doAct(@QueryParameter String dismiss) throws IOException {
         if(dismiss!=null) {
             disable(true);
```
