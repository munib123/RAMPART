# CrossVul Fix Pair: Improper Authentication in java
**Pair ID:** 4521_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4521_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```java
Lines 15-55 of the vulnerable file.

 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 */

package org.opencastproject.kernel.security;

import org.opencastproject.security.api.JaxbOrganization;
import org.opencastproject.security.api.JaxbRole;
import org.opencastproject.security.api.JaxbUser;
import org.opencastproject.security.api.Organization;
import org.opencastproject.security.api.SecurityService;
import org.opencastproject.security.api.User;
import org.opencastproject.security.api.UserDirectoryService;
import org.opencastproject.security.util.SecurityUtil;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * A Spring Security implementation of {@link SecurityService}.
 */
public class SecurityServiceSpringImpl implements SecurityService {

  /** The logger */
  private static final Logger logger = LoggerFactory.getLogger(SecurityServiceSpringImpl.class);

  /** Holds delegates users for new threads that have been spawned from authenticated threads */
  private static final ThreadLocal<User> delegatedUserHolder = new ThreadLocal<User>();

  /** Holds the IP address for the delegated user for the current thread */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,6 +32,7 @@
 
 import org.slf4j.Logger;
 import org.slf4j.LoggerFactory;
+import org.springframework.security.authentication.AnonymousAuthenticationToken;
 import org.springframework.security.core.Authentication;
 import org.springframework.security.core.GrantedAuthority;
 import org.springframework.security.core.context.SecurityContextHolder;
@@ -94,15 +95,19 @@
 
     User delegatedUser = delegatedUserHolder.get();
 
+    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
+    if (auth instanceof AnonymousAuthenticationToken) {
+      return SecurityUtil.createAnonymousUser(org);
+    }
+
     if (delegatedUser != null) {
       return delegatedUser;
     }
 
-    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
     JaxbOrganization jaxbOrganization = JaxbOrganization.fromOrganization(org);
     if (auth != null) {
       Object principal = auth.getPrincipal();
-      if ((principal != null) && (principal instanceof UserDetails)) {
+      if ((principal instanceof UserDetails)) {
         UserDetails userDetails = (UserDetails) principal;
 
         User user = null;
@@ -111,16 +116,15 @@
         if (userDirectory != null) {
           user = userDirectory.loadUser(userDetails.getUsername());
           if (user == null) {
-            logger.debug(
-                    "Authenticated user '{}' could not be found in any of the current UserProviders. Continuing anyway...",
-                    userDetails.getUsername());
+            logger.debug("Authenticated user '{}' could not be found in any of the current UserProviders. "
+                + "Continuing anyway...", userDetails.getUsername());
           }
         } else {
           logger.debug("No UserDirectory was found when trying to search for user '{}'", userDetails.getUsername());
         }
 
         // Add the roles (authorities) in the security context
-        Set<JaxbRole> roles = new HashSet<JaxbRole>();
+        Set<JaxbRole> roles = new HashSet<>();
         Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
         if (authorities != null) {
           for (GrantedAuthority ga : authorities) {
```
