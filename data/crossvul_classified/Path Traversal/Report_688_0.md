# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in java
**Pair ID:** 688_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `688_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```java
Lines 6-46 of the vulnerable file.

 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package spark.resource;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;

import spark.utils.Assert;
import spark.utils.ClassUtils;
import spark.utils.StringUtils;

/**
 * {@link Resource} implementation for class path resources.
 * Uses either a given ClassLoader or a given Class for loading resources.
 * <p>Supports resolution as {@code java.io.File} if the class path
 * resource resides in the file system, but not for resources in a JAR.
 * Always supports resolution as URL.
 *
 * @author Juergen Hoeller
 * @author Sam Brannen
 * @see ClassLoader#getResourceAsStream(String)
 * @see Class#getResourceAsStream(String)
 * Code copied from Spring source. Modifications made (mostly removal of methods) by Per Wendel.
 */
public class ClassPathResource extends AbstractFileResolvingResource {

    private final String path;

    private ClassLoader classLoader;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,6 +23,7 @@
 
 import spark.utils.Assert;
 import spark.utils.ClassUtils;
+import spark.utils.ResourceUtils;
 import spark.utils.StringUtils;
 
 /**
@@ -74,7 +75,7 @@
      */
     public ClassPathResource(String path, ClassLoader classLoader) {
         Assert.notNull(path, "Path must not be null");
-        Assert.state(doesNotContainFileColon(path), "Path must not contain 'file:'");
+        Assert.isTrue(isValid(path), "Path is not valid");
 
         String pathToUse = StringUtils.cleanPath(path);
 
@@ -86,8 +87,27 @@
         this.classLoader = (classLoader != null ? classLoader : ClassUtils.getDefaultClassLoader());
     }
 
-    private static boolean doesNotContainFileColon(String path) {
-        return !path.contains("file:");
+    private static boolean isValid(final String path) {
+        return !isInvalidPath(path);
+    }
+
+    private static boolean isInvalidPath(String path) {
+        if (path.contains("WEB-INF") || path.contains("META-INF")) {
+            return true;
+        }
+        if (path.contains(":/")) {
+            String relativePath = (path.charAt(0) == '/' ? path.substring(1) : path);
+            if (ResourceUtils.isUrl(relativePath) || relativePath.startsWith("url:")) {
+                return true;
+            }
+        }
+        if (path.contains("")) {
+            path = StringUtils.cleanPath(path);
+            if (path.contains("../")) {
+                return true;
+            }
+        }
+        return false;
     }
 
     /**
@@ -236,8 +256,8 @@
             ClassLoader otherLoader = otherRes.classLoader;
 
             return (this.path.equals(otherRes.path) &&
-                thisLoader.equals(otherLoader) &&
-                this.clazz.equals(otherRes.clazz));
+                    thisLoader.equals(otherLoader) &&
+                    this.clazz.equals(otherRes.clazz));
         }
         return false;
     }
```
