# CrossVul Fix Pair: 7PK in java
**Pair ID:** 2398_2
**Vulnerability Class:** 7PK
**CWE:** CWE-254
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2398_2`)

## Vulnerability Information & PoC

## Description
7PK - Security Features

## Vulnerable Code
```java
Lines 1-37 of the vulnerable file.

package jenkins.model;

import hudson.Extension;
import hudson.Util;
import hudson.XmlFile;
import hudson.util.FormValidation;
import hudson.util.XStream2;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.servlet.ServletContext;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.logging.Level;
import java.util.logging.Logger;

import static hudson.Util.fixNull;

/**
 * Stores the location of Jenkins (e-mail address and the HTTP URL.)
 *
 * @author Kohsuke Kawaguchi
 * @since 1.494
 */
@Extension
public class JenkinsLocationConfiguration extends GlobalConfiguration {
    /**
     * @deprecated
     */
    private transient String hudsonUrl;
    private String adminAddress;
    private String jenkinsUrl;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,6 +14,7 @@
 import javax.servlet.ServletContext;
 import java.io.File;
 import java.io.IOException;
+import java.lang.reflect.InvocationTargetException;
 import java.lang.reflect.Method;
 import java.util.logging.Level;
 import java.util.logging.Logger;
@@ -117,14 +118,17 @@
             }
             Object sessionCookieConfig = m.invoke(context);
 
-            // not exposing session cookie to JavaScript to mitigate damage caused by XSS
             Class scc = Class.forName("javax.servlet.SessionCookieConfig");
-            Method setHttpOnly = scc.getMethod("setHttpOnly",boolean.class);
-            setHttpOnly.invoke(sessionCookieConfig,true);
-
-            Method setSecure = scc.getMethod("setSecure",boolean.class);
+            Method setSecure = scc.getMethod("setSecure", boolean.class);
             boolean v = fixNull(jenkinsUrl).startsWith("https");
-            setSecure.invoke(sessionCookieConfig,v);
+            setSecure.invoke(sessionCookieConfig, v);
+        } catch (InvocationTargetException e) {
+            if (e.getTargetException() instanceof IllegalStateException) {
+                // servlet 3.0 spec seems to prohibit this from getting set at runtime,
+                // though Winstone is happy to accept i. see JENKINS-25019
+                return;
+            }
+            LOGGER.log(Level.WARNING, "Failed to set secure cookie flag", e);
         } catch (Exception e) {
             LOGGER.log(Level.WARNING, "Failed to set secure cookie flag", e);
         }
```
