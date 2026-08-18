# CrossVul Fix Pair: Incorrect Authorization in java
**Pair ID:** 1947_3
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1947_3`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```java
Lines 9-49 of the vulnerable file.

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

package org.opencastproject.search.impl.persistence;

import static org.opencastproject.security.api.Permissions.Action.CONTRIBUTE;
import static org.opencastproject.security.api.Permissions.Action.READ;
import static org.opencastproject.security.api.Permissions.Action.WRITE;

import org.opencastproject.mediapackage.MediaPackage;
import org.opencastproject.mediapackage.MediaPackageParser;
import org.opencastproject.security.api.AccessControlList;
import org.opencastproject.security.api.AccessControlParser;
import org.opencastproject.security.api.AccessControlUtil;
import org.opencastproject.security.api.Organization;
import org.opencastproject.security.api.SecurityService;
import org.opencastproject.security.api.UnauthorizedException;
import org.opencastproject.security.api.User;
import org.opencastproject.util.NotFoundException;
import org.opencastproject.util.data.Tuple;

import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.ComponentContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,9 +26,11 @@
 import static org.opencastproject.security.api.Permissions.Action.WRITE;
 
 import org.opencastproject.mediapackage.MediaPackage;
+import org.opencastproject.mediapackage.MediaPackageException;
 import org.opencastproject.mediapackage.MediaPackageParser;
 import org.opencastproject.security.api.AccessControlList;
 import org.opencastproject.security.api.AccessControlParser;
+import org.opencastproject.security.api.AccessControlParsingException;
 import org.opencastproject.security.api.AccessControlUtil;
 import org.opencastproject.security.api.Organization;
 import org.opencastproject.security.api.SecurityService;
@@ -42,6 +44,10 @@
 import org.slf4j.Logger;
 import org.slf4j.LoggerFactory;
 
+import java.io.IOException;
+import java.util.ArrayList;
+import java.util.Arrays;
+import java.util.Collection;
 import java.util.Date;
 import java.util.Iterator;
 import java.util.LinkedList;
@@ -250,11 +256,64 @@
     } catch (NotFoundException e) {
       throw e;
     } catch (Exception e) {
-      logger.error("Could not retrieve ACL {}: {}", mediaPackageId, e.getMessage());
+      logger.error("Could not retrieve ACL {}", mediaPackageId, e);
       throw new SearchServiceDatabaseException(e);
     } finally {
       em.close();
     }
+  }
+
+  /**
+   * {@inheritDoc}
+   *
+   * @see org.opencastproject.search.impl.persistence.SearchServiceDatabase#getAccessControlLists(String, String...)
+   */
+  @Override
+  public Collection<AccessControlList> getAccessControlLists(final String seriesId, String ... excludeIds)
+      throws SearchServiceDatabaseException {
+    List<String> excludes = Arrays.asList(excludeIds);
+    List<AccessControlList> accessControlLists = new ArrayList<>();
+    EntityManager em = emf.createEntityManager();
+    TypedQuery<SearchEntity> q = em.createNamedQuery("Search.findBySeriesId", SearchEntity.class)
+        .setParameter("seriesId", seriesId);
+    try {
+      for (SearchEntity entity: q.getResultList()) {
+        if (entity.getAccessControl() != null && !excludes.contains(entity.getMediaPackageId())) {
+          accessControlLists.add(AccessControlParser.parseAcl(entity.getAccessControl()));
+        }
+      }
+    } catch (IOException | AccessControlParsingException e) {
+      throw new SearchServiceDatabaseException(e);
+    } finally {
+      em.close();
+    }
+    return accessControlLists;
+  }
+
+  /**
+   * {@inheritDoc}
+   *
+   * @see org.opencastproject.search.impl.persistence.SearchServiceDatabase#getMediaPackages(String)
+   */
+  @Override
+  public Collection<MediaPackage> getMediaPackages(final String seriesId)
+      throws SearchServiceDatabaseException {
+    List<MediaPackage> episodes = new ArrayList<>();
+    EntityManager em = emf.createEntityManager();
+    TypedQuery<SearchEntity> q = em.createNamedQuery("Search.findBySeriesId", SearchEntity.class)
+        .setParameter("seriesId", seriesId);
+    try {
+      for (SearchEntity entity: q.getResultList()) {
+        if (entity.getMediaPackageXML() != null) {
+          episodes.add(MediaPackageParser.getFromXml(entity.getMediaPackageXML()));
+        }
+      }
+    } catch (MediaPackageException e) {
+      throw new SearchServiceDatabaseException(e);
+    } finally {
+      em.close();
+    }
+    return episodes;
   }
 
   /**
```
