# CrossVul Fix Pair: Use of Hard-coded Credentials in xml
**Pair ID:** 4528_0
**Vulnerability Class:** Use of Hard-coded Credentials
**CWE:** CWE-798
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4528_0`)

## Vulnerability Information & PoC

## Description
Use of Hard-coded Credentials - Hard-coded credentials typically create a significant hole that allows an attacker to bypass the authentication that has been configured by the product administrator.

## Vulnerable Code
```xml
Lines 309-349 of the vulnerable file.


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
    <sec:custom-filter ref="shibbolethHeaderFilter" position="PRE_AUTH_FILTER"/>
    -->

    <!-- Enables "remember me" functionality -->
    <sec:remember-me key="opencast" user-service-ref="userDetailsService" />

    <!-- Set the request cache -->
    <sec:request-cache ref="requestCache" />

    <!-- If any URLs are to be exposed to anonymous users, the "sec:anonymous" filter must be present -->
    <sec:anonymous enabled="false" />

    <!-- Enables log out -->
    <sec:logout success-handler-ref="logoutSuccessHandler" />

    <!-- Shibboleth log out
         Please specifiy the URL to return to after logging out
    <sec:logout logout-success-url="/Shibboleth.sso/Logout?return=http://www.opencast.org" />
    -->

  </sec:http>

  <!-- ############################# -->
  <!-- # Authentication Filters    # -->
  <!-- ############################# -->
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -326,7 +326,7 @@
     -->
 
     <!-- Enables "remember me" functionality -->
-    <sec:remember-me key="opencast" user-service-ref="userDetailsService" />
+    <sec:remember-me services-ref="rememberMeServices" />
 
     <!-- Set the request cache -->
     <sec:request-cache ref="requestCache" />
@@ -343,6 +343,15 @@
     -->
 
   </sec:http>
+
+  <bean id="rememberMeServices" class="org.opencastproject.kernel.security.SystemTokenBasedRememberMeService">
+    <property name="userDetailsService" ref="userDetailsService"/>
+    <!-- All following settings are optional -->
+    <property name="tokenValiditySeconds" value="1209600"/>
+    <property name="cookieName" value="oc-remember-me"/>
+    <!-- The following key will be augmented by system properties. Thus, leaving this untouched is okay -->
+    <property name="key" value="opencast"/>
+  </bean>
 
   <!-- ############################# -->
   <!-- # Authentication Filters    # -->
```
