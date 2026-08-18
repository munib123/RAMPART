# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 2177_5
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2177_5`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 46-76 of the vulnerable file.


    //Log into DB the user's disconnection
    if (isset($_SESSION['settings']['log_connections']) && $_SESSION['settings']['log_connections'] == 1) {
        logEvents('user_connection', 'disconnection', $_SESSION['user_id']);
    }
} else {
    echo '
    <div style="width:800px;margin:auto;">';
    if (@$_SESSION['error']['code'] == ERR_NOT_ALLOWED) {
        echo '
        <div class="ui-state-error ui-corner-all error" >'.$txt['error_not_authorized'].'</div>';
    } elseif (@$_SESSION['error']['code'] == ERR_NOT_EXIST) {
        echo '
        <div class="ui-state-error ui-corner-all error" >'.$txt['error_not_exists'].'</div>';
    } elseif (@$_SESSION['error']['code'] == ERR_SESS_EXPIRED) {
        echo '
        <div class="ui-state-error ui-corner-all error" style="text-align:center;" >'.$txt['index_session_expired'].'<br /><br /><a href="index.php" />'.$txt['home'] .'</a></div>';
    } elseif (@$_SESSION['error']['code'] == ERR_NO_MCRYPT) {
        echo '
        <div class="ui-state-error ui-corner-all error" style="text-align:center;" >'.$txt['error_mcrypt_not_loaded'].'<br /><br /><a href="index.php" />'.$txt['home'] .'</a></div>';
    }
}

// erase session table
$_SESSION = array();

// Kill session
session_destroy();

echo '
</div>';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -63,6 +63,9 @@
     } elseif (@$_SESSION['error']['code'] == ERR_NO_MCRYPT) {
         echo '
         <div class="ui-state-error ui-corner-all error" style="text-align:center;" >'.$txt['error_mcrypt_not_loaded'].'<br /><br /><a href="index.php" />'.$txt['home'] .'</a></div>';
+    } elseif (@$_SESSION['error']['code'] == ERR_VALID_SESSION) {
+        echo '
+        <div class="ui-state-error ui-corner-all error" style="text-align:center;" >'.$txt['error_not_authorized'].'<br /><br /><a href="index.php" />'.$txt['home'] .'</a></div>';
     }
 }
 
```
