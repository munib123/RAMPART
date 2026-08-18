# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2121_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2121_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 1-30 of the vulnerable file.

<?php
require_once 'base.php';
require_once W2P_BASE_DIR . '/includes/config.php';
require_once W2P_BASE_DIR . '/includes/main_functions.php';
require_once W2P_BASE_DIR . '/includes/db_adodb.php';

$AppUI = new w2p_Core_CAppUI();

$updatekey = w2PgetParam($_POST, 'updatekey', 0);
$contact_id = (int) CContact::getContactByUpdatekey($updatekey);

if (!$contact_id) {
	echo $AppUI->_('You are not authorized to use this page. If you should be authorized please contact the sender to give you another valid link, thank you.');
	exit;
}

$contact = new CContact();
if (!$contact->bind($_POST)) {
	$msg = $AppUI->_('There was an error recording your contact data, please contact the system administrator. Thank you very much.');
} else {

    $result = $contact->store();

    if (is_array($result)) {
        $msg = $AppUI->_('There was an error recording your contact data, please contact the system administrator. Thank you very much.');
    } else {
        $contact->clearUpdateKey();

        $msg = $AppUI->_('Your contact data has been recorded successfully. Your may now close your browser window.  Thank you very much, ' . $contact->contact_first_name);
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,6 +7,7 @@
 $AppUI = new w2p_Core_CAppUI();
 
 $updatekey = w2PgetParam($_POST, 'updatekey', 0);
+$updatekey = preg_replace("/[^A-Za-z0-9]/", "", $updatekey);
 $contact_id = (int) CContact::getContactByUpdatekey($updatekey);
 
 if (!$contact_id) {
```
