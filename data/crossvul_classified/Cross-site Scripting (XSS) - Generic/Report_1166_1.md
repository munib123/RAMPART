# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in java
**Pair ID:** 1166_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1166_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```java
Lines 24-64 of the vulnerable file.

 * If applicable, add the following below the License Header, with the fields
 * enclosed by brackets [] replaced by your own identifying information:
 * "Portions Copyright [year] [name of copyright owner]"
 * 
 * Contributor(s):
 * If you wish your version of this file to be governed by only the CDDL or
 * only the GPL Version 2, indicate your decision by adding "[Contributor]
 * elects to include this software in this distribution under the [CDDL or GPL
 * Version 2] license."  If you don't indicate a single choice of license, a
 * recipient has the option to distribute your version of this file under
 * either the CDDL, the GPL Version 2 or to extend the choice of license to
 * its licensees as provided above.  However, if you add GPL Version 2 code
 * and therefore, elected the GPL Version 2 license, then the option applies
 * only if the new code is made subject to such option by the copyright
 * holder.

 */
package com.sun.faces.lifecycle;

import java.util.Map;
import java.util.regex.Pattern;
import javax.faces.component.UINamingContainer;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.faces.lifecycle.ClientWindow;
import javax.faces.render.ResponseStateManager;
import javax.faces.FacesException;

public class ClientWindowImpl extends ClientWindow {
    
    String id;

    public ClientWindowImpl() {
    }

    @Override
    public Map<String, String> getQueryURLParameters(FacesContext context) {
        return null;
    }
    
    
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -41,13 +41,11 @@
 package com.sun.faces.lifecycle;
 
 import java.util.Map;
-import java.util.regex.Pattern;
 import javax.faces.component.UINamingContainer;
 import javax.faces.context.ExternalContext;
 import javax.faces.context.FacesContext;
 import javax.faces.lifecycle.ClientWindow;
 import javax.faces.render.ResponseStateManager;
-import javax.faces.FacesException;
 
 public class ClientWindowImpl extends ClientWindow {
     
@@ -72,10 +70,6 @@
         // The hidden field always takes precedence, if present.
         if (requestParamMap.containsKey(ResponseStateManager.CLIENT_WINDOW_PARAM)) {
             id = requestParamMap.get(ResponseStateManager.CLIENT_WINDOW_PARAM);
-            Pattern safePattern = Pattern.compile(".*<(.*:script|script).*>[^&]*</\\s*\\1\\s*>.*");
-            if (safePattern.matcher(id).matches()) {
-                throw new FacesException("ClientWindow is illegal: " + id);
-            }
         }
         if (null == id) {
             id = calculateClientWindow(context);
```
