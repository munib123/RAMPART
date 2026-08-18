# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in xml
**Pair ID:** 2294_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2294_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```xml
Lines 94-134 of the vulnerable file.

  </servlet-mapping>

  <servlet>
    <servlet-name>UberFireImageServlet</servlet-name>
    <servlet-class>org.uberfire.server.UberfireImageServlet</servlet-class>
    <init-param>
      <param-name>org.uberfire.images.paths</param-name>
      <param-value>/org.kie.workbench.drools.KIEDroolsWebapp</param-value>
    </init-param>
    <load-on-startup>1</load-on-startup>
  </servlet>

  <servlet-mapping>
    <servlet-name>UberFireImageServlet</servlet-name>
    <url-pattern>/org.kie.workbench.drools.KIEDroolsWebapp/uberFireImages/*</url-pattern>
  </servlet-mapping>

  <servlet>
    <servlet-name>DTableXLSFileServlet</servlet-name>
    <servlet-class>org.drools.workbench.screens.dtablexls.backend.server.DecisionTableXLSFileServlet</servlet-class>
  </servlet>
  <servlet-mapping>
    <servlet-name>DTableXLSFileServlet</servlet-name>
    <url-pattern>/org.kie.workbench.drools.KIEDroolsWebapp/dtablexls/file</url-pattern>
  </servlet-mapping>

  <servlet>
    <servlet-name>ScoreCardFileServlet</servlet-name>
    <servlet-class>org.drools.workbench.screens.scorecardxls.backend.server.ScoreCardXLSFileServlet</servlet-class>
  </servlet>
  <servlet-mapping>
    <servlet-name>ScoreCardFileServlet</servlet-name>
    <url-pattern>/org.kie.workbench.drools.KIEDroolsWebapp/scorecardxls/file</url-pattern>
  </servlet-mapping>

  <servlet>
    <servlet-name>UberfireFileUploadServlet</servlet-name>
    <servlet-class>org.uberfire.server.FileUploadServlet</servlet-class>
  </servlet>
  <servlet-mapping>
    <servlet-name>UberfireFileUploadServlet</servlet-name>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -111,6 +111,14 @@
   <servlet>
     <servlet-name>DTableXLSFileServlet</servlet-name>
     <servlet-class>org.drools.workbench.screens.dtablexls.backend.server.DecisionTableXLSFileServlet</servlet-class>
+    <init-param>
+      <param-name>includes-path</param-name>
+      <param-value>git://**,default://**</param-value>
+    </init-param>
+    <init-param>
+      <param-name>excludes-path</param-name>
+      <param-value>file://**</param-value>
+    </init-param>
   </servlet>
   <servlet-mapping>
     <servlet-name>DTableXLSFileServlet</servlet-name>
@@ -120,6 +128,14 @@
   <servlet>
     <servlet-name>ScoreCardFileServlet</servlet-name>
     <servlet-class>org.drools.workbench.screens.scorecardxls.backend.server.ScoreCardXLSFileServlet</servlet-class>
+    <init-param>
+      <param-name>includes-path</param-name>
+      <param-value>git://**,default://**</param-value>
+    </init-param>
+    <init-param>
+      <param-name>excludes-path</param-name>
+      <param-value>file://**</param-value>
+    </init-param>
   </servlet>
   <servlet-mapping>
     <servlet-name>ScoreCardFileServlet</servlet-name>
@@ -129,6 +145,14 @@
   <servlet>
     <servlet-name>UberfireFileUploadServlet</servlet-name>
     <servlet-class>org.uberfire.server.FileUploadServlet</servlet-class>
+    <init-param>
+      <param-name>includes-path</param-name>
+      <param-value>git://**,default://**</param-value>
+    </init-param>
+    <init-param>
+      <param-name>excludes-path</param-name>
+      <param-value>file://**</param-value>
+    </init-param>
   </servlet>
   <servlet-mapping>
     <servlet-name>UberfireFileUploadServlet</servlet-name>
@@ -138,6 +162,14 @@
   <servlet>
     <servlet-name>UberfireFileDownloadServlet</servlet-name>
     <servlet-class>org.uberfire.server.FileDownloadServlet</servlet-class>
+    <init-param>
+      <param-name>includes-path</param-name>
+      <param-value>git://**,default://**</param-value>
+    </init-param>
+    <init-param>
+      <param-name>excludes-path</param-name>
+      <param-value>file://**</param-value>
+    </init-param>
   </servlet>
   <servlet-mapping>
     <servlet-name>UberfireFileDownloadServlet</servlet-name>
@@ -147,6 +179,14 @@
   <servlet>
     <servlet-name>M2Servlet</servlet-name>
     <servlet-class>org.guvnor.m2repo.backend.server.M2Servlet</servlet-class>
+    <init-param>
+      <param-name>includes-path</param-name>
+      <param-value>git://**,default://**</param-value>
+    </init-param>
+    <init-param>
+      <param-name>excludes-path</param-name>
+      <param-value>file://**</param-value>
+    </init-param>
   </servlet>
   <servlet-mapping>
     <servlet-name>M2Servlet</servlet-name>
@@ -497,6 +537,20 @@
   <!-- security settings -->
   <security-constraint>
     <web-resource-collection>
+      <web-resource-name>download</web-resource-name>
+      <url-pattern>/org.kie.workbench.drools.KIEDroolsWebapp/defaulteditor/upload/*</url-pattern>
+      <url-pattern>/org.kie.workbench.drools.KIEDroolsWebapp/defaulteditor/download/*</url-pattern>
+      <url-pattern>/org.kie.workbench.drools.KIEDroolsWebapp/dtablexls/file</url-pattern>
+      <url-pattern>/org.kie.workbench.drools.KIEDroolsWebapp/scorecardxls/file</url-pattern>
+    </web-resource-collection>
+    <auth-constraint>
+      <role-name>admin</role-name>
+      <role-name>analyst</role-name>
+    </auth-constraint>
+  </security-constraint>
+
+  <security-constraint>
+    <web-resource-collection>
       <web-resource-name>console</web-resource-name>
       <url-pattern>/org.kie.workbench.drools.KIEDroolsWebapp/*</url-pattern>
       <url-pattern>*.erraiBus</url-pattern>
```
