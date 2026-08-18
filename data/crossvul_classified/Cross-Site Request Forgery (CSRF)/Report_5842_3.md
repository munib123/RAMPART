# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in java
**Pair ID:** 5842_3
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5842_3`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```java
Lines 21-61 of the vulnerable file.

//
/////////////////////////////////////////////////////////////////////////////

package org.projectforge.web.admin;

import java.util.SortedSet;

import org.apache.commons.lang.StringUtils;
import org.apache.wicket.AttributeModifier;
import org.apache.wicket.markup.html.WebMarkupContainer;
import org.apache.wicket.markup.html.basic.Label;
import org.apache.wicket.markup.html.form.Button;
import org.apache.wicket.markup.repeater.RepeatingView;
import org.apache.wicket.model.Model;
import org.apache.wicket.model.PropertyModel;
import org.projectforge.Version;
import org.projectforge.continuousdb.UpdateEntry;
import org.projectforge.continuousdb.UpdatePreCheckStatus;
import org.projectforge.web.HtmlHelper;
import org.projectforge.web.wicket.AbstractForm;
import org.projectforge.web.wicket.bootstrap.GridBuilder;
import org.projectforge.web.wicket.components.SingleButtonPanel;
import org.projectforge.web.wicket.flowlayout.CheckBoxPanel;
import org.projectforge.web.wicket.flowlayout.FieldsetPanel;
import org.projectforge.web.wicket.flowlayout.MyComponentsRepeater;

public class SystemUpdateForm extends AbstractForm<SystemUpdateForm, SystemUpdatePage>
{
  private static final long serialVersionUID = 2492737003121592489L;

  protected WebMarkupContainer scripts;

  public boolean showOldUpdateScripts;

  private GridBuilder gridBuilder;

  /**
   * List to create content menu in the desired order before creating the RepeatingView.
   */
  protected MyComponentsRepeater<SingleButtonPanel> actionButtons;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,6 +38,7 @@
 import org.projectforge.continuousdb.UpdatePreCheckStatus;
 import org.projectforge.web.HtmlHelper;
 import org.projectforge.web.wicket.AbstractForm;
+import org.projectforge.web.wicket.CsrfTokenHandler;
 import org.projectforge.web.wicket.bootstrap.GridBuilder;
 import org.projectforge.web.wicket.components.SingleButtonPanel;
 import org.projectforge.web.wicket.flowlayout.CheckBoxPanel;
@@ -55,6 +56,11 @@
   private GridBuilder gridBuilder;
 
   /**
+   * Cross site request forgery token.
+   */
+  private final CsrfTokenHandler csrfTokenHandler;
+
+  /**
    * List to create content menu in the desired order before creating the RepeatingView.
    */
   protected MyComponentsRepeater<SingleButtonPanel> actionButtons;
@@ -62,6 +68,7 @@
   public SystemUpdateForm(final SystemUpdatePage parentPage)
   {
     super(parentPage);
+    csrfTokenHandler = new CsrfTokenHandler(this);
   }
 
   @Override
@@ -165,4 +172,11 @@
     super.onBeforeRender();
     actionButtons.render();
   }
+
+  @Override
+  protected void onSubmit()
+  {
+    super.onSubmit();
+    csrfTokenHandler.onSubmit();
+  }
 }
```
