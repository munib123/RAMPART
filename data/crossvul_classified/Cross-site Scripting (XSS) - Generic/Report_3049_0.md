# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in java
**Pair ID:** 3049_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3049_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```java
Lines 14-54 of the vulnerable file.

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

import hudson.EnvVars;
import hudson.Util;
import hudson.model.queue.SubTask;
import hudson.scm.SCM;
import hudson.tasks.BuildWrapper;
import hudson.tasks.Builder;
import hudson.util.VariableResolver;

import java.io.Serializable;
import java.util.Map;

import net.sf.json.JSONObject;

import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.export.Exported;
import org.kohsuke.stapler.export.ExportedBean;

/**
 * A value for a parameter in a build.
 *
 * Created by {@link ParameterDefinition#createValue(StaplerRequest, JSONObject)} for
 * a particular build (although this 'owner' build object is passed in for every method
 * call as a parameter so that the parameter won't have to persist it.)
 *
 * <h2>Persistence</h2>
 * <p>
 * Instances of {@link ParameterValue}s are persisted into build's <tt>build.xml</tt>
 * through XStream (via {@link ParametersAction}), so instances need to be persistable.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,11 +31,16 @@
 import hudson.tasks.BuildWrapper;
 import hudson.tasks.Builder;
 import hudson.util.VariableResolver;
+import java.io.IOException;
 
 import java.io.Serializable;
 import java.util.Map;
+import java.util.logging.Logger;
+import jenkins.model.Jenkins;
 
 import net.sf.json.JSONObject;
+import org.kohsuke.accmod.Restricted;
+import org.kohsuke.accmod.restrictions.DoNotUse;
 
 import org.kohsuke.stapler.StaplerRequest;
 import org.kohsuke.stapler.export.Exported;
@@ -70,6 +75,9 @@
  */
 @ExportedBean(defaultVisibility=3)
 public abstract class ParameterValue implements Serializable {
+
+    private static final Logger LOGGER = Logger.getLogger(ParameterValue.class.getName());
+
     protected final String name;
 
     private String description;
@@ -89,6 +97,16 @@
 
     public void setDescription(String description) {
         this.description = description;
+    }
+
+    @Restricted(DoNotUse.class) // for value.jelly
+    public String getFormattedDescription() {
+        try {
+            return Jenkins.getInstance().getMarkupFormatter().translate(description);
+        } catch (IOException e) {
+            LOGGER.warning("failed to translate description using configured markup formatter");
+            return "";
+        }
     }
 
     /**
```
