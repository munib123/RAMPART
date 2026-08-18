# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 2878_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2878_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 12-52 of the vulnerable file.

 *
 * @author    Thorsten Rinne <thorsten@phpmyfaq.de>
 * @author    Matteo Scaramuccia <matteo@phpmyfaq.de>
 * @copyright 2003-2017 phpMyFAQ Team
 * @license   http://www.mozilla.org/MPL/2.0/ Mozilla Public License Version 2.0
 *
 * @link      http://www.phpmyfaq.de
 * @since     2003-02-23
 */
if (!defined('IS_VALID_PHPMYFAQ')) {
    $protocol = 'http';
    if (isset($_SERVER['HTTPS']) && strtoupper($_SERVER['HTTPS']) === 'ON') {
        $protocol = 'https';
    }
    header('Location: '.$protocol.'://'.$_SERVER['HTTP_HOST'].dirname($_SERVER['SCRIPT_NAME']));
    exit();
}

$news = new PMF_News($faqConfig);

if ('addnews' == $action && $user->perm->checkRight($user->getUserId(), 'addnews')) {
    ?>
        <header class="row">
            <div class="col-lg-12">
                <h2 class="page-header"><i aria-hidden="true" class="fa fa-pencil"></i> <?php echo $PMF_LANG['ad_news_add'];
    ?></h2>
            </div>
        </header>

        <div class="row">
            <div class="col-lg-12">
                <form class="form-horizontal" id="faqEditor" name="faqEditor" action="?action=savenews" method="post" accept-charset="utf-8">

                    <div class="form-group">
                        <label class="col-lg-2 control-label" for="newsheader">
                            <?php echo $PMF_LANG['ad_news_header'];
    ?>
                        </label>
                        <div class="col-lg-4">
                            <input class="form-control" type="text" name="newsheader">
                        </div>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,12 +29,18 @@
 
 $news = new PMF_News($faqConfig);
 
+$csrfToken = PMF_Filter::filterInput(INPUT_POST, 'csrf', FILTER_SANITIZE_STRING);
+if (!isset($_SESSION['phpmyfaq_csrf_token']) || $_SESSION['phpmyfaq_csrf_token'] !== $csrfToken) {
+    $csrfCheck = false;
+} else {
+    $csrfCheck = true;
+}
+
 if ('addnews' == $action && $user->perm->checkRight($user->getUserId(), 'addnews')) {
     ?>
         <header class="row">
             <div class="col-lg-12">
-                <h2 class="page-header"><i aria-hidden="true" class="fa fa-pencil"></i> <?php echo $PMF_LANG['ad_news_add'];
-    ?></h2>
+                <h2 class="page-header"><i aria-hidden="true" class="fa fa-pencil"></i> <?php echo $PMF_LANG['ad_news_add'] ?></h2>
             </div>
         </header>
 
@@ -44,8 +50,7 @@
 
                     <div class="form-group">
                         <label class="col-lg-2 control-label" for="newsheader">
-                            <?php echo $PMF_LANG['ad_news_header'];
-    ?>
+                            <?php echo $PMF_LANG['ad_news_header'] ?>
                         </label>
                         <div class="col-lg-4">
                             <input class="form-control" type="text" name="newsheader">
@@ -53,8 +58,7 @@
                     </div>
 
                     <div class="form-group">
-                        <label class="col-lg-2 control-label" for="news"><?php echo $PMF_LANG['ad_news_text'];
-    ?>:</label>
+                        <label class="col-lg-2 control-label" for="news"><?php echo $PMF_LANG['ad_news_text'] ?>:</label>
                         <div class="col-lg-4">
                             <noscript>Please enable JavaScript to use the WYSIWYG editor!</noscript>
                             <textarea name="news" rows="5" class="form-control"></textarea>
@@ -62,70 +66,59 @@
                     </div>
 
                     <div class="form-group">
-                        <label class="col-lg-2 control-label" for="authorName"><?php echo $PMF_LANG['ad_news_author_name'];
-    ?></label>
+                        <label class="col-lg-2 control-label" for="authorName"><?php echo $PMF_LANG['ad_news_author_name'] ?></label>
                         <div class="col-lg-4">
                             <input class="form-control" type="text" name="authorName" id="authorName"
-                                   value="<?php echo $user->getUserData('display_name');
-    ?>"/>
-                        </div>
-                    </div>
-
-                    <div class="form-group">
-                        <label class="col-lg-2 control-label" for="authorEmail"><?php echo $PMF_LANG['ad_news_author_email'];
-    ?></label>
+                                   value="<?php echo $user->getUserData('display_name') ?>">
+                        </div>
+                    </div>
+
+                    <div class="form-group">
+                        <label class="col-lg-2 control-label" for="authorEmail"><?php echo $PMF_LANG['ad_news_author_email'] ?></label>
                         <div class="col-lg-4">
                             <input class="form-control" type="email" name="authorEmail" id="authorEmail"
-                                   value="<?php echo $user->getUserData('email');
-    ?>"/>
+                                   value="<?php echo $user->getUserData('email') ?>">
                         </div>
                     </div>
 
                     <div class="form-group">
                         <label class="col-lg-2 control-label" for="active">
-                            <?php echo $PMF_LANG['ad_news_set_active'];
-    ?>:
+                            <?php echo $PMF_LANG['ad_news_set_active'] ?>:
                         </label>
                         <div class="col-lg-4 checkbox">
                             <label>
                                 <input type="checkbox" name="active" id="active" value="y">
-                                <?php echo $PMF_LANG['ad_gen_yes'];
-    ?>
-                            </label>
-                        </div>
-                    </div>
-
-                    <div class="form-group">
-                        <label class="col-lg-2 control-label" for="comment"><?php echo $PMF_LANG['ad_news_allowComments'];
-    ?></label>
+                                <?php echo $PMF_LANG['ad_gen_yes'] ?>
+                            </label>
+                        </div>
+                    </div>
+
+                    <div class="form-group">
+                        <label class="col-lg-2 control-label" for="comment"><?php echo $PMF_LANG['ad_news_allowComments'] ?></label>
                         <div class="col-lg-4 checkbox">
                             <label>
                                 <input type="checkbox" name="comment" id="comment" value="y">
-                                <?php echo $PMF_LANG['ad_gen_yes'];
-    ?>
-                            </label>
-                        </div>
-                    </div>
-
-                    <div class="form-group">
-                        <label class="col-lg-2 control-label" for="link"><?php echo $PMF_LANG['ad_news_link_url'];
-    ?></label>
+                                <?php echo $PMF_LANG['ad_gen_yes'] ?>
+                            </label>
+                        </div>
+                    </div>
+
+                    <div class="form-group">
+                        <label class="col-lg-2 control-label" for="link"><?php echo $PMF_LANG['ad_news_link_url'] ?></label>
                         <div class="col-lg-4">
                             <input class="form-control" type="url" name="link" id="link" placeholder="http://www.example.com/">
                         </div>
                     </div>
 
                     <div class="form-group">
-                        <label class="col-lg-2 control-label" for="linkTitle"><?php echo $PMF_LANG['ad_news_link_title'];
-    ?></label>
+                        <label class="col-lg-2 control-label" for="linkTitle"><?php echo $PMF_LANG['ad_news_link_title'] ?></label>
                         <div class="col-lg-4">
                             <input type="text" name="linkTitle" id="linkTitle" class="form-control">
                         </div>
                     </div>
 
                     <div class="form-group">
-                        <label class="col-lg-2 control-label" ><?php echo $PMF_LANG['ad_news_link_target'];
-    ?></label>
+                        <label class="col-lg-2 control-label" ><?php echo $PMF_LANG['ad_news_link_target'] ?></label>
                         <div class="col-lg-4 radio">
                             <label>
                                 <input type="radio" name="target" value="blank">
@@ -140,16 +133,13 @@
                         </div>
                     </div>
                     <div class="form-group">
-                        <label class="col-lg-2 control-label" for="langTo"><?php echo $PMF_LANG['ad_entry_locale'];
-    ?>:</label>
-                        <div class="col-lg-4">
-                            <?php echo PMF_Language::selectLanguages($LANGCODE, false, [], 'langTo');
-    ?>
-                        </div>
-                    </div>
-
-                    <legend><?php echo $PMF_LANG['ad_news_expiration_window'];
-    ?></legend>
+                        <label class="col-lg-2 control-label" for="langTo"><?php echo $PMF_LANG['ad_entry_locale'] ?>:</label>
+                        <div class="col-lg-4">
+                            <?php echo PMF_Language::selectLanguages($LANGCODE, false, [], 'langTo') ?>
+                        </div>
+                    </div>
+
+                    <legend><?php echo $PMF_LANG['ad_news_expiration_window'] ?></legend>
                     <div class="form-group">
                         <label class="col-lg-2 control-label" for="dateStart"><?php echo $PMF_LANG['ad_news_from'];
     ?></label>
... (diff truncated)
```
