# CrossVul Fix Pair: Improper Authentication in java
**Pair ID:** 2094_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2094_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```java
Lines 1-25 of the vulnerable file.

package jenkins.security;

import hudson.model.User;
import hudson.security.ACL;
import hudson.util.Scrambler;
import org.acegisecurity.context.SecurityContext;
import org.acegisecurity.context.SecurityContextHolder;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * {@link Filter} that performs HTTP basic authentication based on API token.
 *
 * <p>
 * Normally the filter chain would also contain another filter that handles BASIC
 * auth with the real password. Care must be taken to ensure that this doesn't
 * interfere with the other.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,9 +2,13 @@
 
 import hudson.model.User;
 import hudson.security.ACL;
+import hudson.security.UserMayOrMayNotExistException;
 import hudson.util.Scrambler;
+import jenkins.model.Jenkins;
 import org.acegisecurity.context.SecurityContext;
 import org.acegisecurity.context.SecurityContextHolder;
+import org.acegisecurity.userdetails.UsernameNotFoundException;
+import org.springframework.dao.DataAccessException;
 
 import javax.servlet.Filter;
 import javax.servlet.FilterChain;
@@ -41,6 +45,17 @@
             int idx = uidpassword.indexOf(':');
             if (idx >= 0) {
                 String username = uidpassword.substring(0, idx);
+                try {
+                    Jenkins.getInstance().getSecurityRealm().loadUserByUsername(username);
+                } catch (UserMayOrMayNotExistException x) {
+                    // OK, give them the benefit of the doubt.
+                } catch (UsernameNotFoundException x) {
+                    // Not/no longer a user; deny the API token. (But do not leak the information that this happened.)
+                    chain.doFilter(request, response);
+                    return;
+                } catch (DataAccessException x) {
+                    throw new ServletException(x);
+                }
                 String password = uidpassword.substring(idx+1);
 
                 // attempt to authenticate as API token
```
