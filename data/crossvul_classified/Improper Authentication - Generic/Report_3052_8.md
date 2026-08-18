# CrossVul Fix Pair: Improper Authentication in java
**Pair ID:** 3052_8
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3052_8`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```java
Lines 1-28 of the vulnerable file.

package jenkins.security.s2m;

import hudson.Extension;
import hudson.model.AdministrativeMonitor;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.QueryParameter;

import javax.inject.Inject;
import java.io.IOException;

/**
 * If {@link AdminWhitelistRule#masterKillSwitch} is on, warn the user.
 *
 * @author Kohsuke Kawaguchi
 * @since 1.THU
 */
@Extension
public class MasterKillSwitchWarning extends AdministrativeMonitor {
    @Inject
    AdminWhitelistRule rule;

    @Inject
    MasterKillSwitchConfiguration config;

    @Override
    public boolean isActivated() {
        return rule.getMasterKillSwitch() && config.isRelevant();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,6 +5,7 @@
 import org.kohsuke.stapler.HttpResponse;
 import org.kohsuke.stapler.HttpResponses;
 import org.kohsuke.stapler.QueryParameter;
+import org.kohsuke.stapler.interceptor.RequirePOST;
 
 import javax.inject.Inject;
 import java.io.IOException;
@@ -28,6 +29,7 @@
         return rule.getMasterKillSwitch() && config.isRelevant();
     }
 
+    @RequirePOST
     public HttpResponse doAct(@QueryParameter String dismiss) throws IOException {
         if(dismiss!=null) {
             disable(true);
```
