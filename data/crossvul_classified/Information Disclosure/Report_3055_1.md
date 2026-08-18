# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in java
**Pair ID:** 3055_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3055_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```java
Lines 15-55 of the vulnerable file.

 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package hudson.search;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import hudson.model.FreeStyleProject;
import hudson.model.ListView;

import java.net.URL;

import java.util.ArrayList;
import java.util.List;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;

import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.JenkinsRule.WebClient;
import org.jvnet.hudson.test.MockFolder;

import com.gargoylesoftware.htmlunit.AlertHandler;
import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.Page;

/**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,11 +32,19 @@
 import hudson.model.FreeStyleProject;
 import hudson.model.ListView;
 
+import java.io.IOException;
 import java.net.URL;
 
 import java.util.ArrayList;
+import java.util.Collections;
 import java.util.List;
 
+import hudson.model.User;
+import hudson.model.View;
+import hudson.security.ACL;
+import hudson.security.AuthorizationStrategy;
+import hudson.security.GlobalMatrixAuthorizationStrategy;
+import jenkins.model.Jenkins;
 import net.sf.json.JSONArray;
 import net.sf.json.JSONObject;
 import net.sf.json.JSONSerializer;
@@ -378,6 +386,37 @@
 
         assertTrue(suggest(j.jenkins.getSearchIndex(),"foo").contains(p));
     }
+
+    @Issue("SECURITY-385")
+    @Test
+    public void testInaccessibleViews() throws IOException {
+        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
+        GlobalMatrixAuthorizationStrategy strategy = new GlobalMatrixAuthorizationStrategy();
+        strategy.add(Jenkins.READ, "alice");
+        j.jenkins.setAuthorizationStrategy(strategy);
+
+        j.jenkins.addView(new ListView("foo", j.jenkins));
+
+        // SYSTEM can see all the views
+        assertEquals("two views exist", 2, Jenkins.getInstance().getViews().size());
+        List<SearchItem> results = new ArrayList<>();
+        j.jenkins.getSearchIndex().suggest("foo", results);
+        assertEquals("nonempty results list", 1, results.size());
+
+
+        // Alice can't
+        assertFalse("no permission", j.jenkins.getView("foo").getACL().hasPermission(User.get("alice").impersonate(), View.READ));
+        ACL.impersonate(User.get("alice").impersonate(), new Runnable() {
+            @Override
+            public void run() {
+                assertEquals("no visible views", 0, Jenkins.getInstance().getViews().size());
+
+                List<SearchItem> results = new ArrayList<>();
+                j.jenkins.getSearchIndex().suggest("foo", results);
+                assertEquals("empty results list", Collections.emptyList(), results);
+            }
+        });
+    }
     
     @Test
     public void testSearchWithinFolders() throws Exception {
```
