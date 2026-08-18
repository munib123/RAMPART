# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in java
**Pair ID:** 3051_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3051_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

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
package hudson.model;

import static org.junit.Assert.*;

import java.io.File;

import jenkins.model.Jenkins;
import hudson.slaves.DumbSlave;

import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

public class ComputerTest {

    @Rule public JenkinsRule j = new JenkinsRule();

    @Test
    public void discardLogsAfterDeletion() throws Exception {
        DumbSlave delete = j.createOnlineSlave(Jenkins.getInstance().getLabelAtom("delete"));
        DumbSlave keep = j.createOnlineSlave(Jenkins.getInstance().getLabelAtom("keep"));
        File logFile = delete.toComputer().getLogFile();
        assertTrue(logFile.exists());
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,16 +23,22 @@
  */
 package hudson.model;
 
+import static org.hamcrest.Matchers.containsString;
+import static org.hamcrest.Matchers.not;
 import static org.junit.Assert.*;
+
 
 import java.io.File;
 
+import com.gargoylesoftware.htmlunit.xml.XmlPage;
+import hudson.slaves.OfflineCause;
 import jenkins.model.Jenkins;
 import hudson.slaves.DumbSlave;
 
 import org.junit.Rule;
 import org.junit.Test;
 import org.jvnet.hudson.test.JenkinsRule;
+import org.jvnet.hudson.test.recipes.LocalData;
 
 public class ComputerTest {
 
@@ -52,4 +58,27 @@
 
         assertTrue("Slave log should be kept", keep.toComputer().getLogFile().exists());
     }
+
+    @Test
+    public void doNotShowUserDetailsInOfflineCause() throws Exception {
+        DumbSlave slave = j.createOnlineSlave();
+        final Computer computer = slave.toComputer();
+        computer.setTemporarilyOffline(true, new OfflineCause.UserCause(User.get("username"), "msg"));
+        verifyOfflineCause(computer);
+    }
+
+    @Test @LocalData
+    public void removeUserDetailsFromOfflineCause() throws Exception {
+        Computer computer = j.jenkins.getComputer("deserialized");
+        verifyOfflineCause(computer);
+    }
+
+    private void verifyOfflineCause(Computer computer) throws Exception {
+        XmlPage page = j.createWebClient().goToXml("computer/" + computer.getName() + "/config.xml");
+        String content = page.getWebResponse().getContentAsString("UTF-8");
+        assertThat(content, containsString("temporaryOfflineCause"));
+        assertThat(content, containsString("<userId>username</userId>"));
+        assertThat(content, not(containsString("ApiTokenProperty")));
+        assertThat(content, not(containsString("apiToken")));
+    }
 }
```
