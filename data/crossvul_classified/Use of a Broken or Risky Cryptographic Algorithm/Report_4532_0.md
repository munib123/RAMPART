# CrossVul Fix Pair: Use of a Broken or Risky Cryptographic Algorithm in xml
**Pair ID:** 4532_0
**Vulnerability Class:** Use of a Broken or Risky Cryptographic Algorithm
**CWE:** CWE-327
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4532_0`)

## Vulnerability Information & PoC

## Description
Use of a Broken or Risky Cryptographic Algorithm - Cryptographic algorithms are the methods by which data is scrambled to prevent observation or influence by unauthorized actors.

## Vulnerable Code
```xml
Lines 512-548 of the vulnerable file.

  <!-- Obtain services from the OSGI service registry -->
  <osgi:reference id="userDetailsService" cardinality="1..1"
                  interface="org.springframework.security.core.userdetails.UserDetailsService" />

  <osgi:reference id="securityService" cardinality="1..1"
                  interface="org.opencastproject.security.api.SecurityService" />

  <!-- Uncomment to enable external users e.g. used together shibboleth -->
  <!-- <osgi:reference id="userReferenceProvider" cardinality="1..1"
                  interface="org.opencastproject.userdirectory.api.UserReferenceProvider"  /> -->

  <osgi:reference id="userDirectoryService" cardinality="1..1"
                  interface="org.opencastproject.security.api.UserDirectoryService" />

  <osgi:reference id="oAuthConsumerDetailsService" cardinality="1..1"
                  interface="org.springframework.security.oauth.provider.ConsumerDetailsService" />

  <osgi:reference id="ltiLaunchAuthenticationHandler" cardinality="1..1"
                  interface="org.springframework.security.oauth.provider.OAuthAuthenticationHandler" />

  <!-- ############################# -->
  <!-- # Spring Security Internals # -->
  <!-- ############################# -->

  <!-- The JPA user directory stores md5 hashed, salted passwords, so we must use a username-salted md5 password encoder. -->
  <sec:authentication-manager alias="authenticationManager">
    <!-- Uncomment this if using Shibboleth authentication -->
    <!--sec:authentication-provider ref="preauthAuthProvider" /-->
    <sec:authentication-provider user-service-ref="userDetailsService">
      <sec:password-encoder hash="md5"><sec:salt-source user-property="username" /></sec:password-encoder>
    </sec:authentication-provider>
  </sec:authentication-manager>

  <!-- Do not use a request cache -->
  <bean id="requestCache" class="org.springframework.security.web.savedrequest.NullRequestCache" />

</beans>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -529,16 +529,22 @@
   <osgi:reference id="ltiLaunchAuthenticationHandler" cardinality="1..1"
                   interface="org.springframework.security.oauth.provider.OAuthAuthenticationHandler" />
 
+
   <!-- ############################# -->
   <!-- # Spring Security Internals # -->
   <!-- ############################# -->
+
+  <bean id="passwordEncoder" class="org.opencastproject.kernel.security.CustomPasswordEncoder" />
 
   <!-- The JPA user directory stores md5 hashed, salted passwords, so we must use a username-salted md5 password encoder. -->
   <sec:authentication-manager alias="authenticationManager">
     <!-- Uncomment this if using Shibboleth authentication -->
     <!--sec:authentication-provider ref="preauthAuthProvider" /-->
     <sec:authentication-provider user-service-ref="userDetailsService">
-      <sec:password-encoder hash="md5"><sec:salt-source user-property="username" /></sec:password-encoder>
+      <sec:password-encoder ref="passwordEncoder">
+        <!-- This salt is used only for decoding legacy MD5 hased passwords -->
+        <sec:salt-source user-property="username" />
+      </sec:password-encoder>
     </sec:authentication-provider>
   </sec:authentication-manager>
 
```
