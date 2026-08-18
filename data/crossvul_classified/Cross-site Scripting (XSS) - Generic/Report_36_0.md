# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 36_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `36_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 288-328 of the vulnerable file.


        // Try to change the password
        if(!change_password($ui->dn, $_POST['new_password'], FALSE, $method,get_post('current_password'),$msg)){
            msg_dialog::displayChecks(array($msg));
        } else {
            gosa_log("User/password has been changed");
            $smarty->assign("changed", true);
        }
}

/* Parameter fill up */
$params= "";
foreach (array('uid', 'method', 'directory') as $index) {
    $params.= "&amp;$index=".urlencode($$index);
}
$params= preg_replace('/^&amp;/', '?', $params);
$smarty->assign('params', $params);

/* Fill template with required values */
$smarty->assign('date', gmdate("D, d M Y H:i:s"));
$smarty->assign('uid', $uid);
$smarty->assign('password_img', get_template_path('images/password.png'));

/* Displasy SSL mode warning? */
if ($ssl != "" && $config->get_cfg_value("core","warnSSL") == 'true') {
    $smarty->assign(
        "ssl",
        "<b>"._("Warning").":</b> "._("Session will not be encrypted.").
        " <a style=\"color:red;\" href=\"".htmlentities($ssl)."\"><b>".
        _("Enter SSL session")."</b></a>!"
    );
} else {
    $smarty->assign("ssl", "");
}

/* show login screen */
$smarty->assign("JS", session::global_get('js'));
$smarty->assign("PHPSESSID", session_id());
if (session::is_set('errors')) {
    $smarty->assign("errors", session::get('errors'));;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -305,7 +305,7 @@
 
 /* Fill template with required values */
 $smarty->assign('date', gmdate("D, d M Y H:i:s"));
-$smarty->assign('uid', $uid);
+$smarty->assign('uid', set_post($uid));
 $smarty->assign('password_img', get_template_path('images/password.png'));
 
 /* Displasy SSL mode warning? */
```
