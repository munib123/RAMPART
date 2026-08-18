# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in xml
**Pair ID:** 2294_3
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2294_3`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```xml
Lines 86-126 of the vulnerable file.

    <url-pattern>/plugins</url-pattern>
    <url-pattern>/plugin</url-pattern>
    <url-pattern>/plugin/*</url-pattern>
    <url-pattern>/stencilset/*</url-pattern>
  </filter-mapping>

  <servlet>
    <servlet-name>UberFireServlet</servlet-name>
    <servlet-class>org.uberfire.server.UberfireServlet</servlet-class>
    <load-on-startup>1</load-on-startup>
  </servlet>

  <servlet-mapping>
    <servlet-name>UberFireServlet</servlet-name>
    <url-pattern>/org.kie.workbench.drools.KIEDroolsWebapp/KIEDroolsWebapp.html</url-pattern>
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
@@ -103,6 +103,14 @@
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
@@ -112,6 +120,14 @@
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
@@ -121,6 +137,14 @@
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
@@ -130,6 +154,14 @@
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
@@ -139,6 +171,14 @@
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
@@ -489,6 +529,20 @@
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
