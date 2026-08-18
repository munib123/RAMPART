# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in java
**Pair ID:** 2028_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2028_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```java
Lines 1-24 of the vulnerable file.

package io.hawt.web.plugin.karaf.terminal;

import io.hawt.system.Helpers;
import org.apache.felix.service.command.CommandProcessor;
import org.apache.felix.service.command.CommandSession;
import org.apache.felix.service.threadio.ThreadIO;
import org.apache.karaf.shell.console.jline.Console;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.*;
import java.lang.reflect.Constructor;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.util.zip.GZIPOutputStream;

/**
 *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,7 @@
 package io.hawt.web.plugin.karaf.terminal;
 
 import io.hawt.system.Helpers;
+import io.hawt.web.LoginTokenServlet;
 import org.apache.felix.service.command.CommandProcessor;
 import org.apache.felix.service.command.CommandSession;
 import org.apache.felix.service.threadio.ThreadIO;
@@ -8,7 +9,6 @@
 import org.slf4j.Logger;
 import org.slf4j.LoggerFactory;
 
-import javax.security.auth.Subject;
 import javax.servlet.ServletException;
 import javax.servlet.http.HttpServlet;
 import javax.servlet.http.HttpServletRequest;
@@ -16,8 +16,6 @@
 import javax.servlet.http.HttpSession;
 import java.io.*;
 import java.lang.reflect.Constructor;
-import java.security.AccessControlContext;
-import java.security.AccessController;
 import java.util.zip.GZIPOutputStream;
 
 /**
@@ -45,22 +43,17 @@
     protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
 
         HttpSession session = request.getSession(false);
-        if (session == null) {
-          AccessControlContext acc = AccessController.getContext();
-          Subject subject = Subject.getSubject(acc);
-          if (subject == null) {
+        String token = request.getHeader(LoginTokenServlet.LOGIN_TOKEN);
+
+        if (token == null || session == null) {
             Helpers.doForbidden(response);
             return;
-          }
-          session = request.getSession(true);
-          session.setAttribute("subject", subject);
-        } else {
-          Subject subject = (Subject) session.getAttribute("subject");
-          if (subject == null) {
-            session.invalidate();
+        }
+
+        String sessionToken = (String) session.getAttribute(LoginTokenServlet.LOGIN_TOKEN);
+        if (!token.equals(sessionToken)) {
             Helpers.doForbidden(response);
             return;
-          }
         }
 
         String encoding = request.getHeader("Accept-Encoding");
```
