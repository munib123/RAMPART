# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in java
**Pair ID:** 2096_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2096_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```java
Lines 61-101 of the vulnerable file.

import org.kohsuke.stapler.StaplerResponse;
import org.mindrot.jbcrypt.BCrypt;
import org.springframework.dao.DataAccessException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * {@link SecurityRealm} that performs authentication by looking up {@link User}.
 *
 * <p>
 * Implements {@link AccessControlled} to satisfy view rendering, but in reality the access control
 * is done against the {@link jenkins.model.Jenkins} object.
 *
 * @author Kohsuke Kawaguchi
 */
public class HudsonPrivateSecurityRealm extends AbstractPasswordBasedSecurityRealm implements ModelObject, AccessControlled {
    /**
     * If true, sign up is not allowed.
     * <p>
     * This is a negative switch so that the default value 'false' remains compatible with older installations. 
     */
    private final boolean disableSignup;

    /**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -78,6 +78,8 @@
 import java.util.ArrayList;
 import java.util.Collections;
 import java.util.List;
+import java.util.MissingResourceException;
+import java.util.ResourceBundle;
 import java.util.logging.Level;
 import java.util.logging.Logger;
 
@@ -173,8 +175,15 @@
     @Override
     protected Details authenticate(String username, String password) throws AuthenticationException {
         Details u = loadUserByUsername(username);
-        if (!u.isPasswordCorrect(password))
-            throw new BadCredentialsException("Failed to login as "+username);
+        if (!u.isPasswordCorrect(password)) {
+            String message;
+            try {
+                message = ResourceBundle.getBundle("org.acegisecurity.messages").getString("AbstractUserDetailsAuthenticationProvider.badCredentials");
+            } catch (MissingResourceException x) {
+                message = "Bad credentials";
+            }
+            throw new BadCredentialsException(message);
+        }
         return u;
     }
 
```
