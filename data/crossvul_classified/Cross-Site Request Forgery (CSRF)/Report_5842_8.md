# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in java
**Pair ID:** 5842_8
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5842_8`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```java
Lines 22-62 of the vulnerable file.

/////////////////////////////////////////////////////////////////////////////

package org.projectforge.web.dialog;

import org.apache.wicket.AttributeModifier;
import org.apache.wicket.Component;
import org.apache.wicket.ajax.AjaxEventBehavior;
import org.apache.wicket.ajax.AjaxRequestTarget;
import org.apache.wicket.ajax.markup.html.form.AjaxButton;
import org.apache.wicket.feedback.ComponentFeedbackMessageFilter;
import org.apache.wicket.markup.head.IHeaderResponse;
import org.apache.wicket.markup.head.OnDomReadyHeaderItem;
import org.apache.wicket.markup.html.WebMarkupContainer;
import org.apache.wicket.markup.html.basic.Label;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.panel.FeedbackPanel;
import org.apache.wicket.markup.html.panel.Panel;
import org.apache.wicket.model.IModel;
import org.apache.wicket.model.Model;
import org.projectforge.web.core.NavTopPanel;
import org.projectforge.web.wicket.WicketUtils;
import org.projectforge.web.wicket.bootstrap.GridBuilder;
import org.projectforge.web.wicket.components.SingleButtonPanel;
import org.projectforge.web.wicket.flowlayout.MyComponentsRepeater;

import de.micromata.wicket.ajax.AjaxCallback;
import de.micromata.wicket.ajax.AjaxFormSubmitCallback;

/**
 * Base component for the ProjectForge modal dialogs.<br/>
 * This dialog is modal.<br/>
 * 
 * @author Johannes Unterstein (j.unterstein@micromata.de)
 * @author Kai Reinhard (k.reinhard@micromata.de)
 * 
 */
public abstract class ModalDialog extends Panel
{
  private static final long serialVersionUID = 4235521713603821639L;

  protected GridBuilder gridBuilder;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,6 +39,7 @@
 import org.apache.wicket.model.IModel;
 import org.apache.wicket.model.Model;
 import org.projectforge.web.core.NavTopPanel;
+import org.projectforge.web.wicket.CsrfTokenHandler;
 import org.projectforge.web.wicket.WicketUtils;
 import org.projectforge.web.wicket.bootstrap.GridBuilder;
 import org.projectforge.web.wicket.components.SingleButtonPanel;
@@ -98,6 +99,11 @@
   protected MyComponentsRepeater<Component> actionButtons;
 
   /**
+   * Cross site request forgery token.
+   */
+  protected CsrfTokenHandler csrfTokenHandler;
+
+  /**
    * @param id
    */
   public ModalDialog(final String id)
@@ -231,6 +237,7 @@
       @Override
       protected void onEvent(final AjaxRequestTarget target)
       {
+        csrfTokenHandler.onSubmit();
         handleCloseEvent(target);
       }
     });
@@ -288,6 +295,7 @@
 
   public void close(final AjaxRequestTarget target)
   {
+    csrfTokenHandler.onSubmit();
     target.appendJavaScript("$('#" + getMainContainerMarkupId() + "').modal('hide');");
   }
 
@@ -366,6 +374,7 @@
   protected void init(final Form< ? > form)
   {
     this.form = form;
+    csrfTokenHandler = new CsrfTokenHandler(form);
     mainSubContainer.add(form);
     form.add(gridContentContainer);
     form.add(buttonBarContainer);
@@ -374,6 +383,7 @@
         @Override
         public void callback(final AjaxRequestTarget target)
         {
+          csrfTokenHandler.onSubmit();
           onCancelButtonSubmit(target);
           close(target);
         }
@@ -385,6 +395,7 @@
       @Override
       public void callback(final AjaxRequestTarget target)
       {
+        csrfTokenHandler.onSubmit();
         if (onCloseButtonSubmit(target)) {
           close(target);
         }
@@ -393,6 +404,7 @@
       @Override
       public void onError(final AjaxRequestTarget target, final Form< ? > form)
       {
+        csrfTokenHandler.onSubmit();
         ModalDialog.this.onError(target, form);
       }
     }, closeButtonLabel != null ? closeButtonLabel : getString("close"), SingleButtonPanel.NORMAL);
@@ -416,6 +428,7 @@
 
   protected void ajaxError(final String error, final AjaxRequestTarget target)
   {
+    csrfTokenHandler.onSubmit();
     form.error(error);
     target.add(formFeedback);
   }
@@ -427,6 +440,7 @@
    */
   protected void handleCloseEvent(final AjaxRequestTarget target)
   {
+    csrfTokenHandler.onSubmit();
   }
 
   /**
@@ -505,6 +519,7 @@
       @Override
       protected void onSubmit(final AjaxRequestTarget target, final Form< ? > form)
       {
+        csrfTokenHandler.onSubmit();
         ajaxCallback.callback(target);
       }
 
```
