# CrossVul Fix Pair: Improper Authentication in java
**Pair ID:** 3052_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3052_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```java
Lines 7-47 of the vulnerable file.

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
package hudson.diagnosis;

import hudson.model.AdministrativeMonitor;
import jenkins.model.Jenkins;
import hudson.model.AbstractModelObject;
import hudson.Extension;
import hudson.ExtensionPoint;
import hudson.ExtensionList;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.QueryParameter;

import java.io.IOException;
import java.util.List;

/**
 * Monitors the disk usage of <tt>JENKINS_HOME</tt>, and if it's almost filled up, warn the user.
 *
 * @author Kohsuke Kawaguchi
 */
@Extension
public final class HudsonHomeDiskUsageMonitor extends AdministrativeMonitor {
    /**
     * Value updated by {@link HudsonHomeDiskUsageChecker}.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -24,7 +24,6 @@
 package hudson.diagnosis;
 
 import hudson.model.AdministrativeMonitor;
-import jenkins.model.Jenkins;
 import hudson.model.AbstractModelObject;
 import hudson.Extension;
 import hudson.ExtensionPoint;
@@ -32,6 +31,7 @@
 import org.kohsuke.stapler.HttpResponse;
 import org.kohsuke.stapler.HttpResponses;
 import org.kohsuke.stapler.QueryParameter;
+import org.kohsuke.stapler.interceptor.RequirePOST;
 
 import java.io.IOException;
 import java.util.List;
@@ -64,6 +64,7 @@
     /**
      * Depending on whether the user said "yes" or "no", send him to the right place.
      */
+    @RequirePOST
     public HttpResponse doAct(@QueryParameter String no) throws IOException {
         if(no!=null) {
             disable(true);
```
