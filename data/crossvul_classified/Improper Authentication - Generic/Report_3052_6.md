# CrossVul Fix Pair: Improper Authentication in java
**Pair ID:** 3052_6
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3052_6`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```java
Lines 1-34 of the vulnerable file.

package jenkins.security;

import hudson.Extension;
import hudson.init.InitMilestone;
import hudson.init.Initializer;
import hudson.model.TaskListener;
import hudson.util.HttpResponses;
import hudson.util.SecretRewriter;
import hudson.util.VersionNumber;
import jenkins.management.AsynchronousAdministrativeMonitor;
import jenkins.model.Jenkins;
import jenkins.util.io.FileBoolean;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerProxy;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.interceptor.RequirePOST;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.security.GeneralSecurityException;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Warns the administrator to run {@link SecretRewriter}
 *
 * @author Kohsuke Kawaguchi
 */
@Extension
public class RekeySecretAdminMonitor extends AsynchronousAdministrativeMonitor implements StaplerProxy {

    /**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,7 +11,6 @@
 import jenkins.model.Jenkins;
 import jenkins.util.io.FileBoolean;
 import org.kohsuke.stapler.HttpResponse;
-import org.kohsuke.stapler.StaplerProxy;
 import org.kohsuke.stapler.StaplerRequest;
 import org.kohsuke.stapler.interceptor.RequirePOST;
 
@@ -29,7 +28,7 @@
  * @author Kohsuke Kawaguchi
  */
 @Extension
-public class RekeySecretAdminMonitor extends AsynchronousAdministrativeMonitor implements StaplerProxy {
+public class RekeySecretAdminMonitor extends AsynchronousAdministrativeMonitor {
 
     /**
      * Whether we detected a need to run the rewrite program.
@@ -60,14 +59,6 @@
         if (j.isUpgradedFromBefore(new VersionNumber("1.496.*"))
         &&  new FileBoolean(new File(j.getRootDir(),"secret.key.not-so-secret")).isOff())
             needed.on();
-    }
-
-    /**
-     * Requires ADMINISTER permission for any operation in here.
-     */
-    public Object getTarget() {
-        Jenkins.getInstance().checkPermission(Jenkins.ADMINISTER);
-        return this;
     }
 
     @Override
```
