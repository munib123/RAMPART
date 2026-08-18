# CrossVul Fix Pair: Use of a Broken or Risky Cryptographic Algorithm in java
**Pair ID:** 4532_6
**Vulnerability Class:** Use of a Broken or Risky Cryptographic Algorithm
**CWE:** CWE-327
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4532_6`)

## Vulnerability Information & PoC

## Description
Use of a Broken or Risky Cryptographic Algorithm - Cryptographic algorithms are the methods by which data is scrambled to prevent observation or influence by unauthorized actors.

## Vulnerable Code
```java
Lines 12-52 of the vulnerable file.

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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.opencastproject.util.data.Collections.set;
import static org.opencastproject.util.persistence.PersistenceUtil.newTestEntityManagerFactory;

import org.opencastproject.security.api.Role;
import org.opencastproject.security.api.SecurityConstants;
import org.opencastproject.security.api.SecurityService;
import org.opencastproject.security.api.UnauthorizedException;
import org.opencastproject.security.api.User;
import org.opencastproject.security.impl.jpa.JpaOrganization;
import org.opencastproject.security.impl.jpa.JpaRole;
import org.opencastproject.security.impl.jpa.JpaUser;
import org.opencastproject.util.NotFoundException;
import org.opencastproject.util.PasswordEncoder;
import org.opencastproject.util.data.Collections;

import org.apache.commons.collections4.IteratorUtils;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,6 +29,7 @@
 import static org.opencastproject.util.data.Collections.set;
 import static org.opencastproject.util.persistence.PersistenceUtil.newTestEntityManagerFactory;
 
+import org.opencastproject.kernel.security.CustomPasswordEncoder;
 import org.opencastproject.security.api.Role;
 import org.opencastproject.security.api.SecurityConstants;
 import org.opencastproject.security.api.SecurityService;
@@ -38,7 +39,6 @@
 import org.opencastproject.security.impl.jpa.JpaRole;
 import org.opencastproject.security.impl.jpa.JpaUser;
 import org.opencastproject.util.NotFoundException;
-import org.opencastproject.util.PasswordEncoder;
 import org.opencastproject.util.data.Collections;
 
 import org.apache.commons.collections4.IteratorUtils;
@@ -56,6 +56,7 @@
   private JpaUserAndRoleProvider provider = null;
   private JpaOrganization org1 = null;
   private JpaOrganization org2 = null;
+  private CustomPasswordEncoder passwordEncoder = new CustomPasswordEncoder();
 
   @Before
   public void setUp() throws Exception {
@@ -83,7 +84,7 @@
     assertNotNull(loadUser);
 
     assertEquals(user.getUsername(), loadUser.getUsername());
-    assertEquals(PasswordEncoder.encode(user.getPassword(), user.getUsername()), loadUser.getPassword());
+    assertTrue(passwordEncoder.isPasswordValid(loadUser.getPassword(), user.getPassword(), null));
     assertEquals(user.getOrganization(), loadUser.getOrganization());
     assertEquals(user.getRoles(), loadUser.getRoles());
 
@@ -94,7 +95,7 @@
     assertNotNull(loadUser);
 
     assertEquals(user.getUsername(), loadUser.getUsername());
-    assertEquals(PasswordEncoder.encode(user.getPassword(), user.getUsername()), loadUser.getPassword());
+    assertTrue(passwordEncoder.isPasswordValid(loadUser.getPassword(), user.getPassword(), null));
     assertEquals(user.getOrganization(), loadUser.getOrganization());
     assertEquals(user.getRoles(), loadUser.getRoles());
   }
@@ -227,7 +228,7 @@
 
     assertNotNull(loadUpdatedUser);
     assertEquals(user.getUsername(), loadUpdatedUser.getUsername());
-    assertEquals(PasswordEncoder.encode(newPassword, user.getUsername()), loadUpdatedUser.getPassword());
+    assertTrue(passwordEncoder.isPasswordValid(loadUpdatedUser.getPassword(), newPassword, null));
     assertEquals(authorities.size(), loadUpdatedUser.getRoles().size());
 
     updateUser = new JpaUser("unknown", newPassword, org1, provider.getName(), true, authorities);
```
