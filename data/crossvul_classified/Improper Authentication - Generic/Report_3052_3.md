# CrossVul Fix Pair: Improper Authentication in java
**Pair ID:** 3052_3
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3052_3`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```java
Lines 11-51 of the vulnerable file.

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
import hudson.Extension;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;

import java.io.IOException;

/**
 * If Hudson is run with a lot of jobs but no views, suggest the user that they can create views.
 *
 * <p>
 * I noticed at an user visit that some users didn't notice the '+' icon in the tab bar. 
 *
 * @author Kohsuke Kawaguchi
 */
@Extension
public class TooManyJobsButNoView extends AdministrativeMonitor {
    public boolean isActivated() {
        Jenkins h = Jenkins.getInstance();
        return h.getViews().size()==1 && h.getItemMap().size()> THRESHOLD;
    }

    /**
     * Depending on whether the user said "yes" or "no", send him to the right place.
     */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,6 +28,7 @@
 import hudson.Extension;
 import org.kohsuke.stapler.StaplerRequest;
 import org.kohsuke.stapler.StaplerResponse;
+import org.kohsuke.stapler.interceptor.RequirePOST;
 
 import java.io.IOException;
 
@@ -49,6 +50,7 @@
     /**
      * Depending on whether the user said "yes" or "no", send him to the right place.
      */
+    @RequirePOST
     public void doAct(StaplerRequest req, StaplerResponse rsp) throws IOException {
         if(req.hasParameter("no")) {
             disable(true);
```
