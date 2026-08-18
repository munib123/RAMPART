# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 2982_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2982_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 133-173 of the vulnerable file.

  'hit DESC'            => l10n('Visits, high &rarr; low'),
  'hit ASC'             => l10n('Visits, low &rarr; high'),
  'id ASC'              => l10n('Numeric identifier, 1 &rarr; 9'),
  'id DESC'             => l10n('Numeric identifier, 9 &rarr; 1'),
  'rank ASC'            => l10n('Manual sort order'),
  );

$comments_order = array(
  'ASC' => l10n('Show oldest comments first'),
  'DESC' => l10n('Show latest comments first'),
  );

$mail_themes = array(
  'clear' => 'Clear',
  'dark' => 'Dark',
  );

//------------------------------ verification and registration of modifications
if (isset($_POST['submit']))
{
  $int_pattern = '/^\d+$/';

  switch ($page['section'])
  {
    case 'main' :
    {
      if ( !isset($conf['order_by_custom']) and !isset($conf['order_by_inside_category_custom']) )
      {
        if ( !empty($_POST['order_by']) )
        {
          $used = array();
          foreach ($_POST['order_by'] as $i => $val)
          {
            if (empty($val) or isset($used[$val]))
            {
              unset($_POST['order_by'][$i]);
            }
            else
            {
              $used[$val] = true;
            }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -150,6 +150,7 @@
 //------------------------------ verification and registration of modifications
 if (isset($_POST['submit']))
 {
+  check_pwg_token();
   $int_pattern = '/^\d+$/';
 
   switch ($page['section'])
@@ -320,6 +321,7 @@
 $template->assign(
   array(
     'U_HELP' => get_root_url().'admin/popuphelp.php?page=configuration',
+    'PWG_TOKEN' => get_pwg_token(),
     'F_ACTION'=>$action
     ));
 
```
