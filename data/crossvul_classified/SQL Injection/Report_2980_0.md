# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2980_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2980_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 144-184 of the vulnerable file.


$mail_themes = array(
  'clear' => 'Clear',
  'dark' => 'Dark',
  );

//------------------------------ verification and registration of modifications
if (isset($_POST['submit']))
{
  check_pwg_token();
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
          }
          if ( !count($_POST['order_by']) )
          {
            $page['errors'][] = l10n('No order field selected');
          }
          else
          {
            // limit to the number of available parameters
            $order_by = $order_by_inside_category = array_slice($_POST['order_by'], 0, ceil(count($sort_fields)/2));

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -161,6 +161,8 @@
       {
         if ( !empty($_POST['order_by']) )
         {
+          check_input_parameter('order_by', $_POST, true, '/^('.implode('|', array_keys($sort_fields)).')$/');
+
           $used = array();
           foreach ($_POST['order_by'] as $i => $val)
           {
```
