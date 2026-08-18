# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in php
**Pair ID:** 3093_0
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3093_0`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```php
Lines 1-34 of the vulnerable file.

<?php
# Copyright (c) 2003-2005, Jannis Hermanns (on behalf the Serendipity Developer Team)
# All rights reserved.  See LICENSE file for licensing details

#if ($_REQUEST['type'] == 'trackback') die('Disabled');

include('serendipity_config.inc.php');
include S9Y_INCLUDE_PATH . 'include/functions_entries_admin.inc.php';

header('Content-Type: text/html; charset=' . LANG_CHARSET);

if (isset($serendipity['GET']['delete'], $serendipity['GET']['entry'], $serendipity['GET']['type'])) {
    serendipity_deleteComment($serendipity['GET']['delete'], $serendipity['GET']['entry'], $serendipity['GET']['type']);
    if (serendipity_isResponseClean($_SERVER['HTTP_REFERER'])) {
        header('Status: 302 Found');
        header('Location: '. $_SERVER['HTTP_REFERER']);
        exit;
    }
}

if (isset($serendipity['GET']['switch'], $serendipity['GET']['entry'])) {
    serendipity_allowCommentsToggle($serendipity['GET']['entry'], $serendipity['GET']['switch']);
}

if (!empty($_REQUEST['c']) && !empty($_REQUEST['hash'])) {
    $res = serendipity_confirmMail($_REQUEST['c'], $_REQUEST['hash']);
    $serendipity['view'] = 'notification';
    $serendipity['GET']['action'] = 'custom';
    $serendipity['smarty_custom_vars'] = array(
        'content_message'       => ($res ? NOTIFICATION_CONFIRM_MAIL : NOTIFICATION_CONFIRM_MAIL_FAIL),
        'subscribe_confirm_error'				=> !$res,
        'subscribe_confirm_success'				=> $res,
    );
    include S9Y_INCLUDE_PATH . 'include/genpage.inc.php';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,7 +11,7 @@
 
 if (isset($serendipity['GET']['delete'], $serendipity['GET']['entry'], $serendipity['GET']['type'])) {
     serendipity_deleteComment($serendipity['GET']['delete'], $serendipity['GET']['entry'], $serendipity['GET']['type']);
-    if (serendipity_isResponseClean($_SERVER['HTTP_REFERER'])) {
+    if (serendipity_isResponseClean($_SERVER['HTTP_REFERER']) && preg_match('@^https?://' . preg_quote($_SERVER['HTTP_HOST'], '@') . '@imsU')) {
         header('Status: 302 Found');
         header('Location: '. $_SERVER['HTTP_REFERER']);
         exit;
```
