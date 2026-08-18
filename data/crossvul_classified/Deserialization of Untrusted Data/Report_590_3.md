# CrossVul Fix Pair: Deserialization of Untrusted Data in java
**Pair ID:** 590_3
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `590_3`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```java
Lines 11-51 of the vulnerable file.

 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package com.facebook.buck.cli;

import static org.hamcrest.junit.MatcherAssert.assertThat;
import static org.junit.Assume.assumeTrue;

import com.facebook.buck.apple.AppleNativeIntegrationTestUtils;
import com.facebook.buck.apple.toolchain.ApplePlatform;
import com.facebook.buck.testutil.ProcessResult;
import com.facebook.buck.testutil.TemporaryPaths;
import com.facebook.buck.testutil.integration.ProjectWorkspace;
import com.facebook.buck.testutil.integration.TestContext;
import com.facebook.buck.testutil.integration.TestDataHelper;
import com.facebook.buck.util.HumanReadableException;
import com.facebook.buck.util.NamedTemporaryFile;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.hamcrest.Matchers;
import org.junit.Rule;
import org.junit.Test;

public class ParserCacheCommandIntegrationTest {

  @Rule public TemporaryPaths tmp = new TemporaryPaths();

  @Test
  public void testSaveAndLoad() throws IOException {
    assumeTrue(AppleNativeIntegrationTestUtils.isApplePlatformAvailable(ApplePlatform.MACOSX));

    ProjectWorkspace workspace =
        TestDataHelper.createProjectWorkspaceForScenario(this, "parser_with_cell", tmp);
    workspace.setUp();

    // Warm the parser cache.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,17 +28,26 @@
 import com.facebook.buck.testutil.integration.TestDataHelper;
 import com.facebook.buck.util.HumanReadableException;
 import com.facebook.buck.util.NamedTemporaryFile;
+import java.io.FileOutputStream;
 import java.io.IOException;
+import java.io.InvalidClassException;
+import java.io.ObjectOutputStream;
 import java.nio.charset.StandardCharsets;
 import java.nio.file.Files;
 import java.nio.file.Path;
+import java.util.HashMap;
+import java.util.Map;
+import java.util.zip.ZipEntry;
+import java.util.zip.ZipOutputStream;
 import org.hamcrest.Matchers;
 import org.junit.Rule;
 import org.junit.Test;
+import org.junit.rules.ExpectedException;
 
 public class ParserCacheCommandIntegrationTest {
 
   @Rule public TemporaryPaths tmp = new TemporaryPaths();
+  @Rule public ExpectedException thrown = ExpectedException.none();
 
   @Test
   public void testSaveAndLoad() throws IOException {
@@ -146,4 +155,28 @@
           e.getMessage(), Matchers.containsString("//Apps:TestAppsLibrary could not be found"));
     }
   }
+
+  @Test
+  public void testInvalidData() throws IOException {
+    Map<String, String> invalidData = new HashMap();
+    invalidData.put("foo", "bar");
+
+    NamedTemporaryFile tempFile = new NamedTemporaryFile("invalid_parser_data", null);
+    try (FileOutputStream fos = new FileOutputStream(tempFile.get().toString());
+        ZipOutputStream zipos = new ZipOutputStream(fos)) {
+      zipos.putNextEntry(new ZipEntry("parser_data"));
+      try (ObjectOutputStream oos = new ObjectOutputStream(zipos)) {
+        oos.writeObject(invalidData);
+      }
+    }
+
+    ProjectWorkspace workspace =
+        TestDataHelper.createProjectWorkspaceForScenario(this, "parser_with_cell", tmp);
+    workspace.setUp();
+
+    // Load the invalid parser cache data.
+    thrown.expect(InvalidClassException.class);
+    thrown.expectMessage("Can't deserialize this class");
+    workspace.runBuckCommand("parser-cache", "--load", tempFile.get().toString());
+  }
 }
```
