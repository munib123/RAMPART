# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in java
**Pair ID:** 3051_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3051_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

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

package hudson.slaves;

import jenkins.model.Jenkins;
import hudson.Functions;
import hudson.model.Computer;
import hudson.model.User;

import org.jvnet.localizer.Localizable;
import org.kohsuke.stapler.export.ExportedBean;
import org.kohsuke.stapler.export.Exported;

import javax.annotation.Nonnull;
import java.util.Date;

/**
 * Represents a cause that puts a {@linkplain Computer#isOffline() computer offline}.
 *
 * <h2>Views</h2>
 * <p>
 * {@link OfflineCause} must have <tt>cause.jelly</tt> that renders a cause
 * into HTML. This is used to tell users why the node is put offline.
 * This view should render a block element like DIV.
 *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -24,7 +24,6 @@
 
 package hudson.slaves;
 
-import jenkins.model.Jenkins;
 import hudson.Functions;
 import hudson.model.Computer;
 import hudson.model.User;
@@ -33,7 +32,10 @@
 import org.kohsuke.stapler.export.ExportedBean;
 import org.kohsuke.stapler.export.Exported;
 
+import javax.annotation.CheckForNull;
 import javax.annotation.Nonnull;
+import java.io.ObjectStreamException;
+import java.util.Collections;
 import java.util.Date;
 
 /**
@@ -128,21 +130,49 @@
 
     /**
      * Taken offline by user.
+     *
      * @since 1.551
      */
     public static class UserCause extends SimpleOfflineCause {
-        private final User user;
+        @Deprecated
+        private transient User user;
+        // null when unknown
+        private /*final*/ @CheckForNull String userId;
 
-        public UserCause(User user, String message) {
-            super(hudson.slaves.Messages._SlaveComputer_DisconnectedBy(
-                    user!=null ? user.getId() : Jenkins.ANONYMOUS.getName(),
+        public UserCause(@CheckForNull User user, @CheckForNull String message) {
+            this(
+                    user != null ? user.getId() : null,
                     message != null ? " : " + message : ""
-            ));
-            this.user = user;
+            );
+        }
+
+        private UserCause(String userId, String message) {
+            super(hudson.slaves.Messages._SlaveComputer_DisconnectedBy(userId, message));
+            this.userId = userId;
         }
 
         public User getUser() {
-            return user;
+            return userId == null
+                    ? User.getUnknown()
+                    : User.getById(userId, true)
+            ;
+        }
+
+        // Storing the User in a filed was a mistake, switch to userId
+        @SuppressWarnings("deprecation")
+        private Object readResolve() throws ObjectStreamException {
+            if (user != null) {
+                String id = user.getId();
+                if (id != null) {
+                    userId = id;
+                } else {
+                    // The user field is not properly deserialized so id may be missing. Look the user up by fullname
+                    User user = User.get(this.user.getFullName(), true, Collections.emptyMap());
+                    userId = user.getId();
+                }
+                this.user = null;
+            }
+            return this;
         }
     }
 
```
