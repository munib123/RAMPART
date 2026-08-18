# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in java
**Pair ID:** 5842_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5842_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```java
Lines 23-63 of the vulnerable file.


package org.projectforge.web.admin;

import java.util.TimeZone;

import org.apache.commons.lang.StringUtils;
import org.apache.wicket.markup.ComponentTag;
import org.apache.wicket.markup.html.form.Button;
import org.apache.wicket.markup.html.form.PasswordTextField;
import org.apache.wicket.markup.repeater.RepeatingView;
import org.apache.wicket.model.Model;
import org.apache.wicket.model.PropertyModel;
import org.apache.wicket.spring.injection.annot.SpringBean;
import org.apache.wicket.validation.IValidatable;
import org.apache.wicket.validation.IValidator;
import org.projectforge.core.Configuration;
import org.projectforge.core.ConfigurationDO;
import org.projectforge.database.InitDatabaseDao;
import org.projectforge.user.UserDao;
import org.projectforge.web.wicket.AbstractForm;
import org.projectforge.web.wicket.WicketUtils;
import org.projectforge.web.wicket.bootstrap.GridBuilder;
import org.projectforge.web.wicket.components.MaxLengthTextField;
import org.projectforge.web.wicket.components.RequiredMaxLengthTextField;
import org.projectforge.web.wicket.components.SingleButtonPanel;
import org.projectforge.web.wicket.components.TimeZonePanel;
import org.projectforge.web.wicket.flowlayout.DivPanel;
import org.projectforge.web.wicket.flowlayout.DivType;
import org.projectforge.web.wicket.flowlayout.FieldsetPanel;
import org.projectforge.web.wicket.flowlayout.InputPanel;
import org.projectforge.web.wicket.flowlayout.ParTextPanel;
import org.projectforge.web.wicket.flowlayout.PasswordPanel;
import org.projectforge.web.wicket.flowlayout.RadioGroupPanel;

public class SetupForm extends AbstractForm<SetupForm, SetupPage>
{
  private static final long serialVersionUID = -277853572580468505L;

  private static final String MAGIC_PASSWORD = "******";

  @SpringBean(name = "userDao")
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,6 +40,7 @@
 import org.projectforge.database.InitDatabaseDao;
 import org.projectforge.user.UserDao;
 import org.projectforge.web.wicket.AbstractForm;
+import org.projectforge.web.wicket.CsrfTokenHandler;
 import org.projectforge.web.wicket.WicketUtils;
 import org.projectforge.web.wicket.bootstrap.GridBuilder;
 import org.projectforge.web.wicket.components.MaxLengthTextField;
@@ -86,9 +87,15 @@
 
   private String encryptedPassword;
 
+  /**
+   * Cross site request forgery token.
+   */
+  private final CsrfTokenHandler csrfTokenHandler;
+
   public SetupForm(final SetupPage parentPage)
   {
     super(parentPage, "setupform");
+    csrfTokenHandler = new CsrfTokenHandler(this);
   }
 
   @Override
@@ -227,6 +234,7 @@
         @Override
         public final void onSubmit()
         {
+          csrfTokenHandler.onSubmit();
           parentPage.finishSetup();
         }
       };
@@ -237,6 +245,13 @@
     }
   }
 
+  @Override
+  protected void onSubmit()
+  {
+    super.onSubmit();
+    csrfTokenHandler.onSubmit();
+  }
+
   public SetupTarget getSetupMode()
   {
     return setupMode;
```
