# CrossVul Fix Pair: Improper Authentication in java
**Pair ID:** 2029_2
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2029_2`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```java
Lines 1-23 of the vulnerable file.

package io.hawt.web.plugin.karaf.terminal;

import org.apache.felix.service.command.CommandProcessor;
import org.apache.felix.service.command.CommandSession;
import org.apache.felix.service.threadio.ThreadIO;
import org.apache.karaf.shell.console.jline.Console;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.lang.reflect.Constructor;
import java.util.zip.GZIPOutputStream;

/**
 *
 */
public class TerminalServlet extends HttpServlet {

    public static final int TERM_WIDTH = 120;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,6 @@
 package io.hawt.web.plugin.karaf.terminal;
 
+import io.hawt.system.Helpers;
 import org.apache.felix.service.command.CommandProcessor;
 import org.apache.felix.service.command.CommandSession;
 import org.apache.felix.service.threadio.ThreadIO;
@@ -7,12 +8,16 @@
 import org.slf4j.Logger;
 import org.slf4j.LoggerFactory;
 
+import javax.security.auth.Subject;
 import javax.servlet.ServletException;
 import javax.servlet.http.HttpServlet;
 import javax.servlet.http.HttpServletRequest;
 import javax.servlet.http.HttpServletResponse;
+import javax.servlet.http.HttpSession;
 import java.io.*;
 import java.lang.reflect.Constructor;
+import java.security.AccessControlContext;
+import java.security.AccessController;
 import java.util.zip.GZIPOutputStream;
 
 /**
@@ -38,12 +43,32 @@
 
     @Override
     protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
+
+        HttpSession session = request.getSession(false);
+        if (session == null) {
+          AccessControlContext acc = AccessController.getContext();
+          Subject subject = Subject.getSubject(acc);
+          if (subject == null) {
+            Helpers.doForbidden(response);
+            return;
+          }
+          session = request.getSession(true);
+          session.setAttribute("subject", subject);
+        } else {
+          Subject subject = (Subject) session.getAttribute("subject");
+          if (subject == null) {
+            session.invalidate();
+            Helpers.doForbidden(response);
+            return;
+          }
+        }
+
         String encoding = request.getHeader("Accept-Encoding");
         boolean supportsGzip = (encoding != null && encoding.toLowerCase().indexOf("gzip") > -1);
-        SessionTerminal st = (SessionTerminal) request.getSession(true).getAttribute("terminal");
+        SessionTerminal st = (SessionTerminal) session.getAttribute("terminal");
         if (st == null || st.isClosed()) {
             st = new SessionTerminal(getCommandProcessor(), getThreadIO());
-            request.getSession().setAttribute("terminal", st);
+            session.setAttribute("terminal", st);
         }
         String str = request.getParameter("k");
         String f = request.getParameter("f");
```
