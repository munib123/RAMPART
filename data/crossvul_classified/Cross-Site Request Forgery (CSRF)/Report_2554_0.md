# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 2554_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2554_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 21-63 of the vulnerable file.

// | USA.                                                                  |
// +-----------------------------------------------------------------------+

if (!defined('PHPWG_ROOT_PATH'))
{
  die ("Hacking attempt!");
}

include_once(PHPWG_ROOT_PATH.'admin/include/functions.php');
include_once(PHPWG_ROOT_PATH.'admin/include/tabsheet.class.php');

// +-----------------------------------------------------------------------+
// | Check Access and exit when user status is not ok                      |
// +-----------------------------------------------------------------------+
check_status(ACCESS_ADMINISTRATOR);

// +-----------------------------------------------------------------------+
// |                       modification registration                       |
// +-----------------------------------------------------------------------+

// print '<pre>';
// print_r($_POST);
// print '</pre>';
if (isset($_POST['falsify'])
    and isset($_POST['cat_true'])
    and count($_POST['cat_true']) > 0)
{
  switch ($_GET['section'])
  {
    case 'comments' :
    {
      $query = '
UPDATE '.CATEGORIES_TABLE.'
  SET commentable = \'false\'
  WHERE id IN ('.implode(',', $_POST['cat_true']).')
;';
      pwg_query($query);
      break;
    }
    case 'visible' :
    {
      set_cat_visible($_POST['cat_true'], 'false');
      break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,13 +38,12 @@
 // |                       modification registration                       |
 // +-----------------------------------------------------------------------+
 
-// print '<pre>';
-// print_r($_POST);
-// print '</pre>';
+
 if (isset($_POST['falsify'])
     and isset($_POST['cat_true'])
     and count($_POST['cat_true']) > 0)
 {
+  check_pwg_token();
   switch ($_GET['section'])
   {
     case 'comments' :
@@ -246,6 +245,7 @@
 }
 display_select_cat_wrapper($query_true,array(),'category_option_true');
 display_select_cat_wrapper($query_false,array(),'category_option_false');
+$template->assign('PWG_TOKEN',get_pwg_token());
 
 // +-----------------------------------------------------------------------+
 // |                           sending html code                           |
```
