# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2121_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2121_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 1-29 of the vulnerable file.

<?php
require_once 'base.php';
require_once W2P_BASE_DIR . '/includes/config.php';
require_once W2P_BASE_DIR . '/includes/main_functions.php';
require_once W2P_BASE_DIR . '/includes/db_adodb.php';
$AppUI = new w2p_Core_CAppUI();

$updatekey = w2PgetParam($_GET, 'updatekey', 0);
$contact_id = CContact::getContactByUpdatekey($updatekey);

$company_id = intval(w2PgetParam($_REQUEST, 'company_id', 0));
$company_name = w2PgetParam($_REQUEST, 'company_name', null);

// check permissions for this record

if (!$contact_id) {
    echo ($AppUI->_('You are not authorized to use this page. If you should be authorized please contact') . ' ' . $w2Pconfig['company_name'] . ' ' . $AppUI->_('to give you another valid link, thank you.'));
    exit;
}

// load the record data
$msg = '';
$row = new CContact();

if (!$row->load($contact_id) && $contact_id > 0) {
    $AppUI->setMsg('Contact');
    $AppUI->setMsg('invalidID', UI_MSG_ERROR, true);
    $AppUI->redirect();
} else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,6 +6,7 @@
 $AppUI = new w2p_Core_CAppUI();
 
 $updatekey = w2PgetParam($_GET, 'updatekey', 0);
+$updatekey = preg_replace("/[^A-Za-z0-9]/", "", $updatekey);
 $contact_id = CContact::getContactByUpdatekey($updatekey);
 
 $company_id = intval(w2PgetParam($_REQUEST, 'company_id', 0));
```
