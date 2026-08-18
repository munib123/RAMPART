# CrossVul Fix Pair: Credentials Management Errors in java
**Pair ID:** 788_0
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-255
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `788_0`)

## Vulnerability Information & PoC

## Description
Credentials Management Errors

## Vulnerable Code
```java
Lines 5-45 of the vulnerable file.

import org.airsonic.player.service.SettingsService;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class GlobalSecurityConfig extends GlobalAuthenticationConfigurerAdapter {

    private static Logger logger = LoggerFactory.getLogger(GlobalSecurityConfig.class);

    static final String FAILURE_URL = "/login?error=1";

    @Autowired
    private SecurityService securityService;

    @Autowired
    private CsrfSecurityRequestMatcher csrfSecurityRequestMatcher;

    @Autowired
    SettingsService settingsService;

    @Autowired
    CustomUserDetailsContextMapper customUserDetailsContextMapper;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -22,6 +22,8 @@
 import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
 import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
 
+import java.security.SecureRandom;
+
 @Configuration
 @Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
 @EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
@@ -30,6 +32,14 @@
     private static Logger logger = LoggerFactory.getLogger(GlobalSecurityConfig.class);
 
     static final String FAILURE_URL = "/login?error=1";
+
+    private static final String key;
+
+    static {
+      byte[] array = new byte[32];
+      new SecureRandom().nextBytes(array);
+      key = new String(array);
+    }
 
     @Autowired
     private SecurityService securityService;
@@ -162,7 +172,7 @@
                     // see http://docs.spring.io/spring-security/site/docs/3.2.4.RELEASE/reference/htmlsingle/#csrf-logout
                     .and().logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET")).logoutSuccessUrl(
                     "/login?logout")
-                    .and().rememberMe().key("airsonic");
+                    .and().rememberMe().key(key);
         }
 
     }
```
