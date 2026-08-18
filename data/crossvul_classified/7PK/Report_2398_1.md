# CrossVul Fix Pair: 7PK in java
**Pair ID:** 2398_1
**Vulnerability Class:** 7PK
**CWE:** CWE-254
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2398_1`)

## Vulnerability Information & PoC

## Description
7PK - Security Features

## Vulnerable Code
```java
Lines 39-79 of the vulnerable file.

import hudson.util.IncompatibleAntVersionDetected;
import hudson.util.HudsonFailedToLoad;
import hudson.util.ChartUtil;
import hudson.util.AWTProblem;
import org.jvnet.localizer.LocaleProvider;
import org.kohsuke.stapler.jelly.JellyFacet;
import org.apache.tools.ant.types.FileSet;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.ServletResponse;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.Date;
import java.util.Locale;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.security.Security;
import java.util.logging.LogRecord;

import static java.util.logging.Level.*;

/**
 * Entry point when Hudson is used as a webapp.
 *
 * @author Kohsuke Kawaguchi
 */
public class WebAppMain implements ServletContextListener {
    private final RingBufferLogHandler handler = new RingBufferLogHandler() {
        @Override public synchronized void publish(LogRecord record) {
            if (record.getLevel().intValue() >= Level.INFO.intValue()) {
                super.publish(record);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -56,6 +56,7 @@
 import java.io.File;
 import java.io.FileOutputStream;
 import java.io.IOException;
+import java.lang.reflect.Method;
 import java.net.URL;
 import java.net.URLClassLoader;
 import java.util.Date;
@@ -115,6 +116,8 @@
             }
 
             installLogger();
+
+            markCookieAsHttpOnly(context);
 
             final FileAndDescription describedHomeDir = getHomeDir(event);
             home = describedHomeDir.file.getAbsoluteFile();
@@ -251,6 +254,31 @@
         }
     }
 
+    /**
+     * Set the session cookie as HTTP only.
+     *
+     * @see <a href="https://www.owasp.org/index.php/HttpOnly">discussion of this topic in OWASP</a>
+     */
+    private void markCookieAsHttpOnly(ServletContext context) {
+        try {
+            Method m;
+            try {
+                m = context.getClass().getMethod("getSessionCookieConfig");
+            } catch (NoSuchMethodException x) { // 3.0+
+                LOGGER.log(Level.FINE, "Failed to set secure cookie flag", x);
+                return;
+            }
+            Object sessionCookieConfig = m.invoke(context);
+
+            // not exposing session cookie to JavaScript to mitigate damage caused by XSS
+            Class scc = Class.forName("javax.servlet.SessionCookieConfig");
+            Method setHttpOnly = scc.getMethod("setHttpOnly",boolean.class);
+            setHttpOnly.invoke(sessionCookieConfig,true);
+        } catch (Exception e) {
+            LOGGER.log(Level.WARNING, "Failed to set HTTP-only cookie flag", e);
+        }
+    }
+
     public void joinInit() throws InterruptedException {
         initThread.join();
     }
```
