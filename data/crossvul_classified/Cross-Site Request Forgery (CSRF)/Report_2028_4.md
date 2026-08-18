# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in java
**Pair ID:** 2028_4
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2028_4`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```java
Lines 1-33 of the vulnerable file.

package io.hawt.web;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.Principal;
import java.util.ArrayList;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.security.auth.Subject;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import io.hawt.system.ConfigManager;
import io.hawt.system.Helpers;
import org.jolokia.converter.Converters;
import org.jolokia.converter.json.JsonConvertOptions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 */
public class LoginServlet extends HttpServlet {

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,16 +1,12 @@
 package io.hawt.web;
 
-import java.io.IOException;
-import java.io.PrintWriter;
-import java.security.AccessControlContext;
-import java.security.AccessController;
-import java.security.Principal;
-import java.util.ArrayList;
-import java.util.GregorianCalendar;
-import java.util.HashMap;
-import java.util.List;
-import java.util.Map;
-import java.util.Set;
+import io.hawt.system.ConfigManager;
+import io.hawt.system.Helpers;
+import org.jolokia.converter.Converters;
+import org.jolokia.converter.json.JsonConvertOptions;
+import org.slf4j.Logger;
+import org.slf4j.LoggerFactory;
+
 import javax.security.auth.Subject;
 import javax.servlet.ServletConfig;
 import javax.servlet.ServletException;
@@ -18,13 +14,12 @@
 import javax.servlet.http.HttpServletRequest;
 import javax.servlet.http.HttpServletResponse;
 import javax.servlet.http.HttpSession;
-
-import io.hawt.system.ConfigManager;
-import io.hawt.system.Helpers;
-import org.jolokia.converter.Converters;
-import org.jolokia.converter.json.JsonConvertOptions;
-import org.slf4j.Logger;
-import org.slf4j.LoggerFactory;
+import java.io.IOException;
+import java.io.PrintWriter;
+import java.security.AccessControlContext;
+import java.security.AccessController;
+import java.security.Principal;
+import java.util.*;
 
 /**
  *
@@ -34,9 +29,9 @@
     private static final long serialVersionUID = 1L;
     private static final transient Logger LOG = LoggerFactory.getLogger(LoginServlet.class);
 
-    Converters converters = new Converters();
-    JsonConvertOptions options = JsonConvertOptions.DEFAULT;
-    ConfigManager config;
+    protected Converters converters = new Converters();
+    protected JsonConvertOptions options = JsonConvertOptions.DEFAULT;
+    protected ConfigManager config;
     private Integer timeout;
 
     @Override
@@ -74,8 +69,9 @@
                 LOG.warn("No security subject stored in existing session, invalidating");
                 session.invalidate();
                 Helpers.doForbidden(resp);
+                return;
             }
-            returnPrincipals(subject, out);
+            sendResponse(session, subject, out);
             return;
         }
 
@@ -112,10 +108,10 @@
             LOG.debug("Http session timeout for user {} is {} sec.", username, session.getMaxInactiveInterval());
         }
 
-        returnPrincipals(subject, out);
+        sendResponse(session, subject, out);
     }
 
-    private void returnPrincipals(Subject subject, PrintWriter out) {
+    protected void sendResponse(HttpSession session, Subject subject, PrintWriter out) {
 
         Map<String, Object> answer = new HashMap<String, Object>();
 
```
