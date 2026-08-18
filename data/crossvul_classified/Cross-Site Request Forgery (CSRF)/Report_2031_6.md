# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in java
**Pair ID:** 2031_6
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2031_6`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```java
Lines 13-53 of the vulnerable file.

 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import org.w3c.dom.*;

/**
 * Check for location restrictions for CORS based cross browser platform requests
 *
 * @author roland
 * @since 07.04.12
 */
public class CorsChecker extends AbstractChecker<String> {

    private List<Pattern> patterns;

    /**
     * Constructor buiilding up this checker from the XML document provided.
     * CORS sections look like
     * <pre>
     *     &lt;cors&gt;
     *       &lt;allow-origin&gt;http://jolokia.org&lt;allow-origin&gt;
     *       &lt;allow-origin&gt;*://*.jmx4perl.org&gt;
     *     &lt;/cors&gt;
     * </pre>
     *
     * @param pDoc the overall policy documents
     */
    public CorsChecker(Document pDoc) {
        NodeList corsNodes = pDoc.getElementsByTagName("cors");
        if (corsNodes.getLength() > 0) {
            patterns = new ArrayList<Pattern>();
            for (int i = 0; i < corsNodes.getLength(); i++) {
                Node corsNode = corsNodes.item(i);
                NodeList nodes = corsNode.getChildNodes();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,6 +30,8 @@
  */
 public class CorsChecker extends AbstractChecker<String> {
 
+    private boolean strictChecking = false;
+
     private List<Pattern> patterns;
 
     /**
@@ -39,6 +41,8 @@
      *     &lt;cors&gt;
      *       &lt;allow-origin&gt;http://jolokia.org&lt;allow-origin&gt;
      *       &lt;allow-origin&gt;*://*.jmx4perl.org&gt;
+     *
+     *       &lt;strict-checking/&gt;
      *     &lt;/cors&gt;
      * </pre>
      *
@@ -56,10 +60,14 @@
                     if (node.getNodeType() != Node.ELEMENT_NODE) {
                         continue;
                     }
-                    assertNodeName(node,"allow-origin");
-                    String p = node.getTextContent().trim().toLowerCase();
-                    p = Pattern.quote(p).replace("*","\\E.*\\Q");
-                    patterns.add(Pattern.compile("^" + p + "$"));
+                    assertNodeName(node,"allow-origin","strict-checking");
+                    if (node.getNodeName().equals("allow-origin")) {
+                        String p = node.getTextContent().trim().toLowerCase();
+                        p = Pattern.quote(p).replace("*", "\\E.*\\Q");
+                        patterns.add(Pattern.compile("^" + p + "$"));
+                    } else if (node.getNodeName().equals("strict-checking")) {
+                        strictChecking = true;
+                    }
                 }
             }
         }
@@ -68,11 +76,21 @@
     /** {@inheritDoc} */
     @Override
     public boolean check(String pArg) {
+        return check(pArg,false);
+    }
+
+    public boolean check(String pOrigin, boolean pIsStrictCheck) {
+        // Method called during strict checking but we have not configured that
+        // So the check passes always.
+        if (pIsStrictCheck && !strictChecking) {
+            return true;
+        }
+
         if (patterns == null || patterns.size() == 0) {
             return true;
         }
         for (Pattern pattern : patterns) {
-            if (pattern.matcher(pArg).matches()) {
+            if (pattern.matcher(pOrigin).matches()) {
                 return true;
             }
         }
```
