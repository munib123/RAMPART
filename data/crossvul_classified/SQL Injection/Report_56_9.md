# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 56_9
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `56_9`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 431-467 of the vulnerable file.

                    ($MANDATORY_FIELDS['country'] == 'y') ? ' *' : '',
                    ($MANDATORY_FIELDS['zip'] == 'y') ? ' *' : '',
                    ($MANDATORY_FIELDS['tel'] == 'y') ? ' *' : ''
                    ),
        'MISSING0' => ($missing['name']) ? 1 : 0,
        'MISSING1' => ($missing['nick']) ? 1 : 0,
        'MISSING2' => ($missing['password']) ? 1 : 0,
        'MISSING3' => ($missing['repeat_password']) ? 1 : 0,
        'MISSING4' => ($missing['email']) ? 1 : 0,
        'MISSING5' => ($missing['birthday']) ? 1 : 0,
        'MISSING6' => ($missing['address']) ? 1 : 0,
        'MISSING7' => ($missing['city']) ? 1 : 0,
        'MISSING8' => ($missing['prov']) ? 1 : 0,
        'MISSING9' => ($missing['country']) ? 1 : 0,
        'MISSING10' => ($missing['zip']) ? 1 : 0,
        'MISSING11' => ($missing['tel']) ? 1 : 0,
        'FEES'=> $system->print_money($signup_fee),

        'V_YNEWSL' => ((isset($_POST['TPL_nletter']) && $_POST['TPL_nletter'] == 1) || !isset($_POST['TPL_nletter'])) ? 'checked=true' : '',
        'V_NNEWSL' => (isset($_POST['TPL_nletter']) && $_POST['TPL_nletter'] == 2) ? 'checked=true' : '',
        'V_YNAME' => (isset($_POST['TPL_name'])) ? $_POST['TPL_name'] : '',
        'V_UNAME' => (isset($_POST['TPL_nick'])) ? $_POST['TPL_nick'] : '',
        'V_EMAIL' => (isset($_POST['TPL_email'])) ? $_POST['TPL_email'] : '',
        'V_YEAR' => (isset($_POST['TPL_year'])) ? $_POST['TPL_year'] : '',
        'V_ADDRE' => (isset($_POST['TPL_address'])) ? $_POST['TPL_address'] : '',
        'V_CITY' => (isset($_POST['TPL_city'])) ? $_POST['TPL_city'] : '',
        'V_PROV' => (isset($_POST['TPL_prov'])) ? $_POST['TPL_prov'] : '',
        'V_POSTCODE' => (isset($_POST['TPL_zip'])) ? $_POST['TPL_zip'] : '',
        'V_PHONE' => (isset($_POST['TPL_phone'])) ? $_POST['TPL_phone'] : ''
        ));

include 'header.php';
$template->set_filenames(array(
        'body' => 'register.tpl'
        ));
$template->display('body');
include 'footer.php';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -448,15 +448,15 @@
 
         'V_YNEWSL' => ((isset($_POST['TPL_nletter']) && $_POST['TPL_nletter'] == 1) || !isset($_POST['TPL_nletter'])) ? 'checked=true' : '',
         'V_NNEWSL' => (isset($_POST['TPL_nletter']) && $_POST['TPL_nletter'] == 2) ? 'checked=true' : '',
-        'V_YNAME' => (isset($_POST['TPL_name'])) ? $_POST['TPL_name'] : '',
-        'V_UNAME' => (isset($_POST['TPL_nick'])) ? $_POST['TPL_nick'] : '',
-        'V_EMAIL' => (isset($_POST['TPL_email'])) ? $_POST['TPL_email'] : '',
-        'V_YEAR' => (isset($_POST['TPL_year'])) ? $_POST['TPL_year'] : '',
-        'V_ADDRE' => (isset($_POST['TPL_address'])) ? $_POST['TPL_address'] : '',
-        'V_CITY' => (isset($_POST['TPL_city'])) ? $_POST['TPL_city'] : '',
-        'V_PROV' => (isset($_POST['TPL_prov'])) ? $_POST['TPL_prov'] : '',
-        'V_POSTCODE' => (isset($_POST['TPL_zip'])) ? $_POST['TPL_zip'] : '',
-        'V_PHONE' => (isset($_POST['TPL_phone'])) ? $_POST['TPL_phone'] : ''
+        'V_YNAME' => (isset($_POST['TPL_name'])) ? $system->cleanvars($_POST['TPL_name']) : '',
+        'V_UNAME' => (isset($_POST['TPL_nick'])) ? $system->cleanvars($_POST['TPL_nick']) : '',
+        'V_EMAIL' => (isset($_POST['TPL_email'])) ? $system->cleanvars($_POST['TPL_email']) : '',
+        'V_YEAR' => (isset($_POST['TPL_year'])) ? $system->cleanvars($_POST['TPL_year']) : '',
+        'V_ADDRE' => (isset($_POST['TPL_address'])) ? $system->cleanvars($_POST['TPL_address']) : '',
+        'V_CITY' => (isset($_POST['TPL_city'])) ? $system->cleanvars($_POST['TPL_city']) : '',
+        'V_PROV' => (isset($_POST['TPL_prov'])) ? $system->cleanvars($_POST['TPL_prov']) : '',
+        'V_POSTCODE' => (isset($_POST['TPL_zip'])) ? $system->cleanvars($_POST['TPL_zip']) : '',
+        'V_PHONE' => (isset($_POST['TPL_phone'])) ? $system->cleanvars($_POST['TPL_phone']) : ''
         ));
 
 include 'header.php';
```
