# CrossVul Fix Pair: Improper Authentication in java
**Pair ID:** 3052_5
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3052_5`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```java
Lines 1-28 of the vulnerable file.

package jenkins.diagnostics;

import hudson.Extension;
import hudson.model.AdministrativeMonitor;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;

import java.io.IOException;

/**
 * Unsecured Jenkins is, well, insecure.
 *
 * <p>
 * Call attention to the fact that Jenkins is not secured, and encourage the administrator
 * to take an action.
 *
 * @author Kohsuke Kawaguchi
 */
@Extension
public class SecurityIsOffMonitor extends AdministrativeMonitor {
    @Override
    public boolean isActivated() {
        return !Jenkins.getInstance().isUseSecurity();
    }

    /**
     * Depending on whether the user said "yes" or "no", send him to the right place.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,6 +5,7 @@
 import jenkins.model.Jenkins;
 import org.kohsuke.stapler.StaplerRequest;
 import org.kohsuke.stapler.StaplerResponse;
+import org.kohsuke.stapler.interceptor.RequirePOST;
 
 import java.io.IOException;
 
@@ -27,6 +28,7 @@
     /**
      * Depending on whether the user said "yes" or "no", send him to the right place.
      */
+    @RequirePOST
     public void doAct(StaplerRequest req, StaplerResponse rsp) throws IOException {
         if(req.hasParameter("no")) {
             disable(true);
```
