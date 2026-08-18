# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in java
**Pair ID:** 2091_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2091_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```java
Lines 6-46 of the vulnerable file.

 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package hudson.tasks;

import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import hudson.maven.MavenModuleSet;
import hudson.maven.MavenModuleSetBuild;
import hudson.model.FreeStyleBuild;
import hudson.model.FreeStyleProject;
import hudson.model.Result;
import hudson.model.Run;
import org.jvnet.hudson.test.ExtractResourceSCM;
import org.jvnet.hudson.test.HudsonTestCase;
import org.jvnet.hudson.test.MockBuilder;

/**
 * Tests for hudson.tasks.BuildTrigger
 * @author Alan.Harder@sun.com
 */
public class BuildTriggerTest extends HudsonTestCase {

    private FreeStyleProject createDownstreamProject() throws Exception {
        FreeStyleProject dp = createFreeStyleProject("downstream");

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,14 +23,26 @@
  */
 package hudson.tasks;
 
+import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
 import com.gargoylesoftware.htmlunit.html.HtmlForm;
 import com.gargoylesoftware.htmlunit.html.HtmlPage;
+import com.gargoylesoftware.htmlunit.html.HtmlTextInput;
 import hudson.maven.MavenModuleSet;
 import hudson.maven.MavenModuleSetBuild;
 import hudson.model.FreeStyleBuild;
 import hudson.model.FreeStyleProject;
+import hudson.model.Item;
 import hudson.model.Result;
 import hudson.model.Run;
+import hudson.security.AuthorizationMatrixProperty;
+import hudson.security.LegacySecurityRealm;
+import hudson.security.Permission;
+import hudson.security.ProjectMatrixAuthorizationStrategy;
+import java.util.Collections;
+import java.util.HashMap;
+import java.util.Map;
+import java.util.Set;
+import jenkins.model.Jenkins;
 import org.jvnet.hudson.test.ExtractResourceSCM;
 import org.jvnet.hudson.test.HudsonTestCase;
 import org.jvnet.hudson.test.MockBuilder;
@@ -131,4 +143,36 @@
     public void testMavenTriggerEvenWhenUnstable() throws Exception {
         doMavenTriggerTest(true);
     }
+
+    public void testConfigureDownstreamProjectSecurity() throws Exception {
+        jenkins.setSecurityRealm(new LegacySecurityRealm());
+        ProjectMatrixAuthorizationStrategy auth = new ProjectMatrixAuthorizationStrategy();
+        auth.add(Jenkins.READ, "alice");
+        jenkins.setAuthorizationStrategy(auth);
+        FreeStyleProject upstream = createFreeStyleProject("upstream");
+        Map<Permission,Set<String>> perms = new HashMap<Permission,Set<String>>();
+        perms.put(Item.READ, Collections.singleton("alice"));
+        perms.put(Item.CONFIGURE, Collections.singleton("alice"));
+        upstream.addProperty(new AuthorizationMatrixProperty(perms));
+        FreeStyleProject downstream = createFreeStyleProject("downstream");
+        /* Original SECURITY-55 test case:
+        downstream.addProperty(new AuthorizationMatrixProperty(Collections.singletonMap(Item.READ, Collections.singleton("alice"))));
+        */
+        WebClient wc = createWebClient();
+        wc.login("alice");
+        HtmlPage page = wc.getPage(upstream, "configure");
+        HtmlForm config = page.getFormByName("config");
+        config.getButtonByCaption("Add post-build action").click(); // lib/hudson/project/config-publishers2.jelly
+        page.getAnchorByText("Build other projects").click();
+        HtmlTextInput childProjects = config.getInputByName("buildTrigger.childProjects");
+        childProjects.setValueAttribute("downstream");
+        try {
+            submit(config);
+            fail();
+        } catch (FailingHttpStatusCodeException x) {
+            assertEquals(403, x.getStatusCode());
+        }
+        assertEquals(Collections.emptyList(), upstream.getDownstreamProjects());
+    }
+
 }
```
