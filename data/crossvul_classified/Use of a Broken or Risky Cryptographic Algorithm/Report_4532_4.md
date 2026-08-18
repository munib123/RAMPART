# CrossVul Fix Pair: Use of a Broken or Risky Cryptographic Algorithm in java
**Pair ID:** 4532_4
**Vulnerability Class:** Use of a Broken or Risky Cryptographic Algorithm
**CWE:** CWE-327
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4532_4`)

## Vulnerability Information & PoC

## Description
Use of a Broken or Risky Cryptographic Algorithm - Cryptographic algorithms are the methods by which data is scrambled to prevent observation or influence by unauthorized actors.

## Vulnerable Code
```java
Lines 4-44 of the vulnerable file.

 * information regarding copyright ownership.
 *
 *
 * The Apereo Foundation licenses this file to you under the Educational
 * Community License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License
 * at:
 *
 *   http://opensource.org/licenses/ecl2.txt
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 */

package org.opencastproject.userdirectory;

import org.opencastproject.security.api.Group;
import org.opencastproject.security.api.Role;
import org.opencastproject.security.api.RoleProvider;
import org.opencastproject.security.api.SecurityService;
import org.opencastproject.security.api.UnauthorizedException;
import org.opencastproject.security.api.User;
import org.opencastproject.security.api.UserProvider;
import org.opencastproject.security.impl.jpa.JpaOrganization;
import org.opencastproject.security.impl.jpa.JpaRole;
import org.opencastproject.security.impl.jpa.JpaUser;
import org.opencastproject.userdirectory.utils.UserDirectoryUtils;
import org.opencastproject.util.NotFoundException;
import org.opencastproject.util.PasswordEncoder;
import org.opencastproject.util.data.Monadics;
import org.opencastproject.util.data.Option;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;

import org.apache.commons.lang3.StringUtils;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,6 +21,7 @@
 
 package org.opencastproject.userdirectory;
 
+import org.opencastproject.kernel.security.CustomPasswordEncoder;
 import org.opencastproject.security.api.Group;
 import org.opencastproject.security.api.Role;
 import org.opencastproject.security.api.RoleProvider;
@@ -33,7 +34,6 @@
 import org.opencastproject.security.impl.jpa.JpaUser;
 import org.opencastproject.userdirectory.utils.UserDirectoryUtils;
 import org.opencastproject.util.NotFoundException;
-import org.opencastproject.util.PasswordEncoder;
 import org.opencastproject.util.data.Monadics;
 import org.opencastproject.util.data.Option;
 
@@ -57,6 +57,7 @@
 import javax.persistence.EntityManager;
 import javax.persistence.EntityManagerFactory;
 import javax.persistence.EntityTransaction;
+import javax.persistence.TypedQuery;
 
 /**
  * Manages and locates users using JPA.
@@ -94,6 +95,9 @@
 
   /** A token to store in the miss cache */
   protected Object nullToken = new Object();
+
+  /** Password encoder for storing user passwords */
+  private CustomPasswordEncoder passwordEncoder = new CustomPasswordEncoder();
 
   /** OSGi DI */
   void setEntityManagerFactory(EntityManagerFactory emf) {
@@ -177,6 +181,23 @@
   }
 
   /**
+   * List all users with insecure password hashes
+   */
+  public List<User> findInsecurePasswordHashes() {
+    final String orgId = securityService.getOrganization().getId();
+    EntityManager em = null;
+    try {
+      em = emf.createEntityManager();
+      TypedQuery<User> q = em.createNamedQuery("User.findInsecureHash", User.class);
+      q.setParameter("org", orgId);
+      return q.getResultList();
+    } finally {
+      if (em != null)
+        em.close();
+    }
+  }
+
+  /**
    * {@inheritDoc}
    *
    * @see org.opencastproject.security.api.RoleProvider#findRoles(String, Role.Target, int, int)
@@ -271,11 +292,26 @@
    *          if the user is not allowed to create other user with the given roles
    */
   public void addUser(JpaUser user) throws UnauthorizedException {
+    addUser(user, false);
+  }
+
+  /**
+   * Adds a user to the persistence
+   *
+   * @param user
+   *          the user to add
+   * @param passwordEncoded
+   *          if the password is already encoded or should be encoded
+   *
+   * @throws org.opencastproject.security.api.UnauthorizedException
+   *          if the user is not allowed to create other user with the given roles
+   */
+  public void addUser(JpaUser user, final boolean passwordEncoded) throws UnauthorizedException {
     if (!UserDirectoryUtils.isCurrentUserAuthorizedHandleRoles(securityService, user.getRoles()))
       throw new UnauthorizedException("The user is not allowed to set the admin role on other users");
 
     // Create a JPA user with an encoded password.
-    String encodedPassword = PasswordEncoder.encode(user.getPassword(), user.getUsername());
+    String encodedPassword = passwordEncoded ? user.getPassword() : passwordEncoder.encodePassword(user.getPassword());
 
     // Only save internal roles
     Set<JpaRole> roles = UserDirectoryPersistenceUtil.saveRoles(filterRoles(user.getRoles()), emf);
@@ -317,6 +353,21 @@
    *          if the current user is not allowed to update user with the given roles
    */
   public User updateUser(JpaUser user) throws NotFoundException, UnauthorizedException {
+    return updateUser(user, false);
+  }
+
+  /**
+   * Updates a user to the persistence
+   *
+   * @param user
+   *          the user to save
+   * @param passwordEncoded
+   *          if the password is already encoded or should be encoded
+   * @throws NotFoundException
+   * @throws org.opencastproject.security.api.UnauthorizedException
+   *          if the current user is not allowed to update user with the given roles
+   */
+  public User updateUser(JpaUser user, final boolean passwordEncoded) throws NotFoundException, UnauthorizedException {
     if (!UserDirectoryUtils.isCurrentUserAuthorizedHandleRoles(securityService, user.getRoles()))
       throw new UnauthorizedException("The user is not allowed to set the admin role on other users");
 
@@ -336,7 +387,11 @@
       encodedPassword = updateUser.getPassword();
     } else  {
       // Update an JPA user with an encoded password.
-      encodedPassword = PasswordEncoder.encode(user.getPassword(), user.getUsername());
+      if (passwordEncoded) {
+        encodedPassword = user.getPassword();
+      } else {
+        encodedPassword = passwordEncoder.encodePassword(user.getPassword());
+      }
     }
 
     // Only save internal roles
```
