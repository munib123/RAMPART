# CrossVul Fix Pair: Improper Authentication in java
**Pair ID:** 3052_2
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3052_2`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```java
Lines 19-59 of the vulnerable file.

 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package hudson.diagnosis;

import hudson.Extension;
import hudson.Util;
import hudson.model.AdministrativeMonitor;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.QueryParameter;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.Stapler;

/**
 * Looks out for a broken reverse proxy setup that doesn't rewrite the location header correctly.
 *
 * <p>
 * Have the JavaScript make an AJAX call, to which we respond with 302 redirect. If the reverse proxy
 * is done correctly, this will be handled by {@link #doFoo()}, but otherwise we'll report that as an error.
 * Unfortunately, {@code XmlHttpRequest} doesn't expose properties that allow the client-side JavaScript
 * to learn the details of the failure, so we have to make do with limited information.
 *
 * @author Kohsuke Kawaguchi
 */
@Extension
public class ReverseProxySetupMonitor extends AdministrativeMonitor {

    private static final Logger LOGGER = Logger.getLogger(ReverseProxySetupMonitor.class.getName());

    @Override
    public boolean isActivated() {
        // return true to always inject an HTML fragment to perform a test
        return true;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -36,6 +36,7 @@
 import java.util.logging.Logger;
 import jenkins.model.Jenkins;
 import org.kohsuke.stapler.Stapler;
+import org.kohsuke.stapler.interceptor.RequirePOST;
 
 /**
  * Looks out for a broken reverse proxy setup that doesn't rewrite the location header correctly.
@@ -85,6 +86,7 @@
     /**
      * Depending on whether the user said "yes" or "no", send him to the right place.
      */
+    @RequirePOST
     public HttpResponse doAct(@QueryParameter String no) throws IOException {
         if(no!=null) { // dismiss
             disable(true);
```
