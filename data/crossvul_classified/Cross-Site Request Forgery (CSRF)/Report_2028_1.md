# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in xml
**Pair ID:** 2028_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2028_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```xml
Lines 1-36 of the vulnerable file.

<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://java.sun.com/xml/ns/j2ee"
	      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	      xsi:schemaLocation="http://java.sun.com/xml/ns/j2ee
	      http://java.sun.com/xml/ns/j2ee/web-app_2_4.xsd"
	      version="2.4">

  <description>hawtio</description>
  <display-name>hawtio Karaf terminal plugin</display-name>

  <filter>
    <filter-name>AuthenticationFilter</filter-name>
    <filter-class>io.hawt.web.AuthenticationFilter</filter-class>
  </filter>
  <filter-mapping>
    <filter-name>AuthenticationFilter</filter-name>
    <url-pattern>/term/*</url-pattern>
  </filter-mapping>


  <servlet>
    <servlet-name>TerminalServlet</servlet-name>
    <servlet-class>io.hawt.web.plugin.karaf.terminal.TerminalServlet</servlet-class>
    <load-on-startup>1</load-on-startup>
  </servlet>
  <servlet-mapping>
    <servlet-name>TerminalServlet</servlet-name>
    <url-pattern>/term/*</url-pattern>
  </servlet-mapping>

  <listener>
    <listener-class>io.hawt.web.plugin.karaf.terminal.KarafTerminalContextListener</listener-class>
  </listener>

</web-app>

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,7 +16,28 @@
     <filter-name>AuthenticationFilter</filter-name>
     <url-pattern>/term/*</url-pattern>
   </filter-mapping>
+  <filter-mapping>
+    <filter-name>AuthenticationFilter</filter-name>
+    <url-pattern>/auth/*</url-pattern>
+  </filter-mapping>
 
+  <servlet>
+    <servlet-name>login</servlet-name>
+    <servlet-class>io.hawt.web.LoginTokenServlet</servlet-class>
+  </servlet>
+  <servlet-mapping>
+    <servlet-name>login</servlet-name>
+    <url-pattern>/auth/login/*</url-pattern>
+  </servlet-mapping>
+
+  <servlet>
+    <servlet-name>logout</servlet-name>
+    <servlet-class>io.hawt.web.LogoutServlet</servlet-class>
+  </servlet>
+  <servlet-mapping>
+    <servlet-name>logout</servlet-name>
+    <url-pattern>/auth/logout/*</url-pattern>
+  </servlet-mapping>
 
   <servlet>
     <servlet-name>TerminalServlet</servlet-name>
```
