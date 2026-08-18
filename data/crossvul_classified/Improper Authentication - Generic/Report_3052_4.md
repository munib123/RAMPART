# CrossVul Fix Pair: Improper Authentication in java
**Pair ID:** 3052_4
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3052_4`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```java
Lines 17-57 of the vulnerable file.

 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package hudson.model;

import hudson.ExtensionPoint;
import hudson.ExtensionList;
import hudson.Extension;
import hudson.ExtensionPoint.LegacyInstancesAreScopedToHudson;
import hudson.triggers.SCMTrigger;
import hudson.triggers.TimerTrigger;

import java.util.Set;
import java.io.IOException;

import jenkins.model.Jenkins;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;

/**
 * Checks the health of a subsystem of Jenkins and if there's something
 * that requires administrator's attention, notify the administrator.
 *
 * <h2>How to implement?</h2>
 * <p>
 * Plugins who wish to contribute such notifications can implement this
 * class and put {@link Extension} on it to register it to Jenkins.
 *
 * <p>
 * Once installed, it's the implementer's responsibility to perform
 * monitoring and activate/deactivate the monitor accordingly. Sometimes
 * this can be done by updating a flag from code (see {@link SCMTrigger}
 * for one such example), while other times it's more convenient to do
 * so by running some code periodically (for this, use {@link TimerTrigger#timer})
 *
 * <p>
 * {@link AdministrativeMonitor}s are bound to URL by {@link Jenkins#getAdministrativeMonitor(String)}.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -34,8 +34,12 @@
 import java.io.IOException;
 
 import jenkins.model.Jenkins;
+import org.kohsuke.accmod.Restricted;
+import org.kohsuke.accmod.restrictions.NoExternalUse;
+import org.kohsuke.stapler.StaplerProxy;
 import org.kohsuke.stapler.StaplerRequest;
 import org.kohsuke.stapler.StaplerResponse;
+import org.kohsuke.stapler.interceptor.RequirePOST;
 
 /**
  * Checks the health of a subsystem of Jenkins and if there's something
@@ -75,7 +79,7 @@
  * @see Jenkins#administrativeMonitors
  */
 @LegacyInstancesAreScopedToHudson
-public abstract class AdministrativeMonitor extends AbstractModelObject implements ExtensionPoint {
+public abstract class AdministrativeMonitor extends AbstractModelObject implements ExtensionPoint, StaplerProxy {
     /**
      * Human-readable ID of this monitor, which needs to be unique within the system.
      *
@@ -143,10 +147,19 @@
     /**
      * URL binding to disable this monitor.
      */
+    @RequirePOST
     public void doDisable(StaplerRequest req, StaplerResponse rsp) throws IOException {
-        Jenkins.getInstance().checkPermission(Jenkins.ADMINISTER);
         disable(true);
         rsp.sendRedirect2(req.getContextPath()+"/manage");
+    }
+
+    /**
+     * Requires ADMINISTER permission for any operation in here.
+     */
+    @Restricted(NoExternalUse.class)
+    public Object getTarget() {
+        Jenkins.getInstance().checkPermission(Jenkins.ADMINISTER);
+        return this;
     }
 
     /**
```
