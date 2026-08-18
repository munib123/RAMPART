# CrossVul Fix Pair: Incorrect Default Permissions in xml
**Pair ID:** 4534_0
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-276
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4534_0`)

## Vulnerability Information & PoC

## Description
Incorrect Default Permissions - During installation, installed file permissions are set to allow anyone to modify those files.

## Vulnerable Code
```xml
Lines 280-324 of the vulnerable file.


    <!-- Enable capture agent updates and ingest -->
    <sec:intercept-url pattern="/capture-admin/**" access="ROLE_ADMIN, ROLE_CAPTURE_AGENT" />
    <sec:intercept-url pattern="/recordings/**" method="GET" access="ROLE_ADMIN, ROLE_CAPTURE_AGENT" />
    <sec:intercept-url pattern="/ingest/**" access="ROLE_ADMIN, ROLE_CAPTURE_AGENT" />

    <!-- Secure the user management URLs for admins only -->
    <sec:intercept-url pattern="/users/**" access="ROLE_ADMIN" />
    <sec:intercept-url pattern="/admin/users.html" access="ROLE_ADMIN" />

    <!-- Enable 2-legged OAuth access ("signed fetch") to the LTI launch servlet -->
    <sec:intercept-url pattern="/lti" access="ROLE_OAUTH_USER" />

    <!-- Enable access to the LTI tools -->
    <sec:intercept-url pattern="/ltitools/**" access="ROLE_OAUTH_USER" />

    <sec:intercept-url pattern="/transcripts/watson/results*" method="GET" access="ROLE_ANONYMOUS" />
    <sec:intercept-url pattern="/transcripts/watson/results*" method="POST" access="ROLE_ANONYMOUS" />

    <!-- Everything else is for the admin users -->
    <sec:intercept-url pattern="/admin-ng" method="GET" access="ROLE_ADMIN, ROLE_ADMIN_UI, ROLE_COURSE_ADMIN" />
    <sec:intercept-url pattern="/admin-ng/" method="GET" access="ROLE_ADMIN, ROLE_ADMIN_UI, ROLE_COURSE_ADMIN" />
    <sec:intercept-url pattern="/admin-ng/index.html" access="ROLE_ADMIN, ROLE_ADMIN_UI, ROLE_COURSE_ADMIN" />
    <sec:intercept-url pattern="/index.html" access="ROLE_ADMIN, ROLE_ADMIN_UI, ROLE_COURSE_ADMIN" />
    <sec:intercept-url pattern="/**" access="ROLE_ADMIN, ROLE_COURSE_ADMIN" />

    <!-- ############################# -->
    <!-- # LOGIN / LOGOUT MECHANISMS # -->
    <!-- ############################# -->

    <!-- Uncomment to enable x509 client certificates for identifying clients -->
    <!-- sec:x509 subject-principal-regex="CN=(.*?)," user-service-ref="userDetailsService" / -->

    <!-- Enable and configure the failure URL for form-based logins -->
    <sec:form-login authentication-failure-url="/admin-ng/login.html?error" authentication-success-handler-ref="authSuccessHandler" />

    <!-- Authentication filter chain -->
    <sec:custom-filter position="BASIC_AUTH_FILTER" ref="authenticationFilters" />

    <sec:custom-filter ref="asyncTimeoutRedirectFilter" after="EXCEPTION_TRANSLATION_FILTER"/>

    <!-- Opencast is shipping its own implementation of the anonymous filter -->
    <sec:custom-filter ref="anonymousFilter" position="ANONYMOUS_FILTER" />

    <!-- Shibboleth header authentication filter
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -297,11 +297,11 @@
     <sec:intercept-url pattern="/transcripts/watson/results*" method="POST" access="ROLE_ANONYMOUS" />
 
     <!-- Everything else is for the admin users -->
-    <sec:intercept-url pattern="/admin-ng" method="GET" access="ROLE_ADMIN, ROLE_ADMIN_UI, ROLE_COURSE_ADMIN" />
-    <sec:intercept-url pattern="/admin-ng/" method="GET" access="ROLE_ADMIN, ROLE_ADMIN_UI, ROLE_COURSE_ADMIN" />
-    <sec:intercept-url pattern="/admin-ng/index.html" access="ROLE_ADMIN, ROLE_ADMIN_UI, ROLE_COURSE_ADMIN" />
-    <sec:intercept-url pattern="/index.html" access="ROLE_ADMIN, ROLE_ADMIN_UI, ROLE_COURSE_ADMIN" />
-    <sec:intercept-url pattern="/**" access="ROLE_ADMIN, ROLE_COURSE_ADMIN" />
+    <sec:intercept-url pattern="/admin-ng" method="GET" access="ROLE_ADMIN, ROLE_ADMIN_UI" />
+    <sec:intercept-url pattern="/admin-ng/" method="GET" access="ROLE_ADMIN, ROLE_ADMIN_UI" />
+    <sec:intercept-url pattern="/admin-ng/index.html" access="ROLE_ADMIN, ROLE_ADMIN_UI" />
+    <sec:intercept-url pattern="/index.html" access="ROLE_ADMIN, ROLE_ADMIN_UI" />
+    <sec:intercept-url pattern="/**" access="ROLE_ADMIN" />
 
     <!-- ############################# -->
     <!-- # LOGIN / LOGOUT MECHANISMS # -->
```
