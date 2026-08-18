# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in java
**Pair ID:** 3048_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3048_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```java
Lines 10-50 of the vulnerable file.

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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import hudson.security.ACL;
import hudson.security.AccessDeniedException2;
import hudson.security.GlobalMatrixAuthorizationStrategy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.servlet.ServletInputStream;
import javax.servlet.ServletOutputStream;

import org.acegisecurity.context.SecurityContext;
import org.acegisecurity.context.SecurityContextHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,6 +27,8 @@
 import static org.hamcrest.Matchers.containsString;
 import static org.hamcrest.Matchers.equalTo;
 import static org.hamcrest.Matchers.startsWith;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertTrue;
 import static org.mockito.Mockito.spy;
 import static org.mockito.Mockito.when;
 import hudson.security.ACL;
@@ -47,6 +49,7 @@
 import org.junit.Before;
 import org.junit.Rule;
 import org.junit.Test;
+import org.jvnet.hudson.test.Issue;
 import org.jvnet.hudson.test.JenkinsRule;
 import org.jvnet.hudson.test.JenkinsRule.DummySecurityRealm;
 import org.kohsuke.stapler.StaplerRequest;
@@ -140,6 +143,26 @@
         assertThat(updatedSlave.getNumExecutors(), equalTo(42));
     }
 
+    @Test
+    @Issue("SECURITY-343")
+    public void emptyNodeMonitorDataWithoutConnect() throws Exception {
+        rule.jenkins.setAuthorizationStrategy(new GlobalMatrixAuthorizationStrategy());
+
+        assertTrue(computer.getMonitorData().isEmpty());
+    }
+
+    @Test
+    @Issue("SECURITY-343")
+    public void populatedNodeMonitorDataWithConnect() throws Exception {
+        GlobalMatrixAuthorizationStrategy auth = new GlobalMatrixAuthorizationStrategy();
+        rule.jenkins.setAuthorizationStrategy(auth);
+        auth.add(Computer.CONNECT, "user");
+
+        assertFalse(computer.getMonitorData().isEmpty());
+    }
+
+
+
     private OutputStream captureOutput() throws IOException {
 
         final ByteArrayOutputStream baos = new ByteArrayOutputStream();
```
