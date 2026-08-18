# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 1738_0
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1738_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 12-52 of the vulnerable file.

 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package io.milton.http;

import io.milton.resource.AccessControlledResource;
import io.milton.resource.AccessControlledResource.Priviledge;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 *
 * @author brad
 */
public class AclUtils {
    
    /**
     * Recurisve function which checks the given collection of priviledges, 
     * and checks inside the contains property of those priviledges
     * 
     * Returns true if the required priviledge is directly present in the collection
     * or is implied
     * 
     * @param required
     * @param privs
     * @return 
     */
    public static boolean containsPriviledge(AccessControlledResource.Priviledge required, Iterable<AccessControlledResource.Priviledge> privs) {
        for (AccessControlledResource.Priviledge p : privs) {
            if (p.equals(required)) {
                return true;
            }
            if( containsPriviledge(required, p.contains)) {
                return true;
            }
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,19 +29,22 @@
  * @author brad
  */
 public class AclUtils {
-    
+
     /**
-     * Recurisve function which checks the given collection of priviledges, 
+     * Recurisve function which checks the given collection of priviledges,
      * and checks inside the contains property of those priviledges
-     * 
+     *
      * Returns true if the required priviledge is directly present in the collection
      * or is implied
-     * 
+     *
      * @param required
      * @param privs
-     * @return 
+     * @return
      */
     public static boolean containsPriviledge(AccessControlledResource.Priviledge required, Iterable<AccessControlledResource.Priviledge> privs) {
+        if( privs == null ) {
+            return false;
+        }
         for (AccessControlledResource.Priviledge p : privs) {
             if (p.equals(required)) {
                 return true;
@@ -51,18 +54,18 @@
             }
         }
         return false;
-    }      
-    
+    }
+
     public static Set<AccessControlledResource.Priviledge> asSet(AccessControlledResource.Priviledge ... privs) {
         Set<AccessControlledResource.Priviledge> set = new HashSet<AccessControlledResource.Priviledge>(privs.length);
         set.addAll(Arrays.asList(privs));
         return set;
     }
-    
+
     /**
-     * Return a set containing all privs in the given collection, and also all priviledges 
+     * Return a set containing all privs in the given collection, and also all priviledges
      * implies by those, and so on recursively
-     * 
+     *
      * @param privs
      * @return - a set containiing all priviledges, direct or implied, by the given collection
      */
@@ -71,7 +74,7 @@
         _expand(privs, set);
         return set;
     }
-    
+
     private static void _expand(Iterable<AccessControlledResource.Priviledge> privs, Set<AccessControlledResource.Priviledge> output) {
         if( privs == null ) {
             return ;
@@ -80,6 +83,6 @@
             output.add(p);
             _expand(p.contains, output);
         }
-        
+
     }
 }
```
