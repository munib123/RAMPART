# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in java
**Pair ID:** 5842_6
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5842_6`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```java
Lines 42-82 of the vulnerable file.

import org.apache.wicket.model.Model;
import org.apache.wicket.model.PropertyModel;
import org.apache.wicket.request.http.WebRequest;
import org.apache.wicket.request.http.WebResponse;
import org.apache.wicket.request.mapper.parameter.PageParameters;
import org.projectforge.access.AccessChecker;
import org.projectforge.user.PFUserContext;
import org.projectforge.user.UserRights;
import org.projectforge.user.UserXmlPreferencesCache;
import org.projectforge.web.FavoritesMenu;
import org.projectforge.web.LayoutSettingsPage;
import org.projectforge.web.LoginPage;
import org.projectforge.web.MenuEntry;
import org.projectforge.web.core.menuconfig.MenuConfig;
import org.projectforge.web.dialog.ModalDialog;
import org.projectforge.web.doc.DocumentationPage;
import org.projectforge.web.mobile.MenuMobilePage;
import org.projectforge.web.user.ChangePasswordPage;
import org.projectforge.web.user.MyAccountEditPage;
import org.projectforge.web.wicket.AbstractSecuredPage;
import org.projectforge.web.wicket.FeedbackPage;
import org.projectforge.web.wicket.MySession;
import org.projectforge.web.wicket.WicketUtils;
import org.projectforge.web.wicket.flowlayout.FieldsetPanel;

/**
 * Displays the favorite menu.
 * @author Kai Reinhard (k.reinhard@micromata.de)
 */
public class NavTopPanel extends NavAbstractPanel
{
  private static final org.apache.log4j.Logger log = org.apache.log4j.Logger.getLogger(NavTopPanel.class);

  private static final long serialVersionUID = -7858806882044188339L;

  private FavoritesMenu favoritesMenu;

  private final AccessChecker accessChecker;

  private final UserXmlPreferencesCache userXmlPreferencesCache;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -59,6 +59,7 @@
 import org.projectforge.web.user.ChangePasswordPage;
 import org.projectforge.web.user.MyAccountEditPage;
 import org.projectforge.web.wicket.AbstractSecuredPage;
+import org.projectforge.web.wicket.CsrfTokenHandler;
 import org.projectforge.web.wicket.FeedbackPage;
 import org.projectforge.web.wicket.MySession;
 import org.projectforge.web.wicket.WicketUtils;
@@ -81,6 +82,11 @@
   private final UserXmlPreferencesCache userXmlPreferencesCache;
 
   private BookmarkDialog bookmarkDialog;
+
+  /**
+   * Cross site request forgery token.
+   */
+  private CsrfTokenHandler csrfTokenHandler;
 
   public NavTopPanel(final String id, final UserXmlPreferencesCache userXmlPreferencesCache, final AccessChecker accessChecker)
   {
@@ -117,6 +123,7 @@
       @Override
       protected void onSubmit()
       {
+        csrfTokenHandler.onSubmit();
         if (StringUtils.isNotBlank(searchString) == true) {
           final SearchPage searchPage = new SearchPage(new PageParameters(), searchString);
           setResponsePage(searchPage);
@@ -124,6 +131,7 @@
         super.onSubmit();
       }
     };
+    csrfTokenHandler = new CsrfTokenHandler(searchForm);
     add(searchForm);
     final TextField<String> searchField = new TextField<String>("searchField", new PropertyModel<String>(searchForm, "searchString"));
     WicketUtils.setPlaceHolderAttribute(searchField, getString("search.search"));
```
