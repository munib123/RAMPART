# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 56_14
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `56_14`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 107-135 of the vulnerable file.

                exit;
            }

            if (isset($_SESSION['REDIRECT_AFTER_LOGIN'])) {
                $URL = str_replace('\r', '', str_replace('\n', '', $_SESSION['REDIRECT_AFTER_LOGIN']));
                unset($_SESSION['REDIRECT_AFTER_LOGIN']);
            } else {
                $URL = 'user_menu.php';
            }

            header('location: ' . $URL);
            exit;
        }
    } else {
        $ERR = $ERR_038;
    }
}

$template->assign_vars(array(
        'ERROR' => (isset($ERR)) ? $ERR : '',
        'USER' => (isset($_POST['username'])) ? $_POST['username'] : ''
        ));

include 'header.php';
$template->set_filenames(array(
        'body' => 'user_login.tpl'
        ));
$template->display('body');
include 'footer.php';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -124,7 +124,7 @@
 
 $template->assign_vars(array(
         'ERROR' => (isset($ERR)) ? $ERR : '',
-        'USER' => (isset($_POST['username'])) ? $_POST['username'] : ''
+        'USER' => (isset($_POST['username'])) ? $system->cleanvars($_POST['username']) : ''
         ));
 
 include 'header.php';
```
