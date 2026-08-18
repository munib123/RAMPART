# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in java
**Pair ID:** 5842_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5842_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```java
Lines 12-52 of the vulnerable file.

// by the Free Software Foundation; version 3 of the License.
//
// This community edition is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
// Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, see http://www.gnu.org/licenses/.
//
/////////////////////////////////////////////////////////////////////////////

package org.projectforge.web.admin;

import org.apache.wicket.markup.html.form.Button;
import org.apache.wicket.markup.html.form.upload.FileUploadField;
import org.apache.wicket.markup.repeater.RepeatingView;
import org.apache.wicket.model.Model;
import org.apache.wicket.util.lang.Bytes;
import org.projectforge.web.wicket.AbstractForm;
import org.projectforge.web.wicket.bootstrap.GridBuilder;
import org.projectforge.web.wicket.components.SingleButtonPanel;
import org.projectforge.web.wicket.flowlayout.FieldsetPanel;
import org.projectforge.web.wicket.flowlayout.FileUploadPanel;

public class SetupImportForm extends AbstractForm<SetupImportForm, SetupPage>
{
  private static final long serialVersionUID = -277853572580468505L;

  protected FileUploadField fileUploadField;

  protected String filename;

  public SetupImportForm(final SetupPage parentPage)
  {
    super(parentPage, "importform");
    initUpload(Bytes.megabytes(100));
  }

  @Override
  @SuppressWarnings("serial")
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,6 +29,7 @@
 import org.apache.wicket.model.Model;
 import org.apache.wicket.util.lang.Bytes;
 import org.projectforge.web.wicket.AbstractForm;
+import org.projectforge.web.wicket.CsrfTokenHandler;
 import org.projectforge.web.wicket.bootstrap.GridBuilder;
 import org.projectforge.web.wicket.components.SingleButtonPanel;
 import org.projectforge.web.wicket.flowlayout.FieldsetPanel;
@@ -42,10 +43,23 @@
 
   protected String filename;
 
+  /**
+   * Cross site request forgery token.
+   */
+  private final CsrfTokenHandler csrfTokenHandler;
+
   public SetupImportForm(final SetupPage parentPage)
   {
     super(parentPage, "importform");
     initUpload(Bytes.megabytes(100));
+    csrfTokenHandler = new CsrfTokenHandler(this);
+  }
+
+  @Override
+  protected void onSubmit()
+  {
+    super.onSubmit();
+    csrfTokenHandler.onSubmit();
   }
 
   @Override
```
