# CrossVul Fix Pair: Incorrect Authorization in java
**Pair ID:** 1947_2
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1947_2`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```java
Lines 10-50 of the vulnerable file.

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

import org.opencastproject.mediapackage.MediaPackage;
import org.opencastproject.security.api.AccessControlList;
import org.opencastproject.security.api.UnauthorizedException;
import org.opencastproject.util.NotFoundException;
import org.opencastproject.util.data.Tuple;

import java.util.Date;
import java.util.Iterator;

/**
 * API that defines persistent storage of series.
 *
 */
public interface SearchServiceDatabase {

  /**
   * Returns all search entries in persistent storage.
   *
   * @return {@link Tuple} array representing stored media packages
   * @throws SearchServiceDatabaseException
   *           if exception occurs
   */
  Iterator<Tuple<MediaPackage, String>> getAllMediaPackages() throws SearchServiceDatabaseException;

  /**
   * Returns the organization id of the selected media package
   *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,6 +27,7 @@
 import org.opencastproject.util.NotFoundException;
 import org.opencastproject.util.data.Tuple;
 
+import java.util.Collection;
 import java.util.Date;
 import java.util.Iterator;
 
@@ -81,7 +82,18 @@
   MediaPackage getMediaPackage(String mediaPackageId) throws NotFoundException, SearchServiceDatabaseException;
 
   /**
-   * Retrieves ACL for series with given ID.
+   * Gets media packages from a specific series
+   *
+   * @param seriesId
+   *          the series identifier
+   * @return collection of media packages
+   * @throws SearchServiceDatabaseException
+   *           if there is a problem communicating with the underlying data store
+   */
+  Collection<MediaPackage> getMediaPackages(String seriesId) throws SearchServiceDatabaseException;
+
+  /**
+   * Retrieves ACL for episode with given ID.
    *
    * @param mediaPackageId
    *          media package for which ACL will be retrieved
@@ -92,7 +104,21 @@
    *           if exception occurred
    */
   AccessControlList getAccessControlList(String mediaPackageId) throws NotFoundException,
-          SearchServiceDatabaseException;
+      SearchServiceDatabaseException;
+
+  /**
+   * Retrieves ACLs for series with given ID.
+   *
+   * @param seriesId
+   *          series identifier for which ACL will be retrieved
+   * @param excludeIds
+   *          list of media package identifier to exclude from the list
+   * @return Collection of {@link AccessControlList} of media packages from the series
+   * @throws SearchServiceDatabaseException
+   *           if exception occurred
+   */
+  Collection<AccessControlList> getAccessControlLists(String seriesId, String ... excludeIds)
+      throws SearchServiceDatabaseException;
 
   /**
    * Returns the modification date from the selected media package.
```
