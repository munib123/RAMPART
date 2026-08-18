# CrossVul Fix Pair: Cryptographic Issues in java
**Pair ID:** 2093_1
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2093_1`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

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
package hudson.model;

import net.sf.json.JSONObject;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.DataBoundConstructor;
import hudson.Extension;
import hudson.util.Secret;

/**
 * Parameter whose value is a {@link Secret} and is hidden from the UI.
 *
 * @author Kohsuke Kawaguchi
 * @since 1.319
 */
public class PasswordParameterDefinition extends SimpleParameterDefinition {

    private Secret defaultValue;

    @DataBoundConstructor
    public PasswordParameterDefinition(String name, String defaultValue, String description) {
        super(name, description);
        this.defaultValue = Secret.fromString(defaultValue);
    }

    @Override
    public ParameterDefinition copyWithDefaultValue(ParameterValue defaultValue) {
        if (defaultValue instanceof PasswordParameterValue) {
            PasswordParameterValue value = (PasswordParameterValue) defaultValue;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,6 +28,8 @@
 import org.kohsuke.stapler.DataBoundConstructor;
 import hudson.Extension;
 import hudson.util.Secret;
+import org.kohsuke.accmod.Restricted;
+import org.kohsuke.accmod.restrictions.DoNotUse;
 
 /**
  * Parameter whose value is a {@link Secret} and is hidden from the UI.
@@ -76,6 +78,11 @@
         return Secret.toString(defaultValue);
     }
 
+    @Restricted(DoNotUse.class) // used from Jelly
+    public Secret getDefaultValueAsSecret() {
+        return defaultValue;
+    }
+
     // kept for backward compatibility
     public void setDefaultValue(String defaultValue) {
         this.defaultValue = Secret.fromString(defaultValue);
```
