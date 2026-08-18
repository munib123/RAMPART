# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5680_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5680_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 38-78 of the vulnerable file.

        if ($reset != '') {
            $users = Jojo::selectQuery("SELECT userid, us_email, us_login, us_reminder FROM {user} WHERE us_reset= ? LIMIT 1", array($reset));

            if (!count($users)) {
                $errors[] = 'This password reset code has expired. Please use the form below to generate another reset code.';
            } else {
                $userid = $users[0]['userid'];
                $newpassword = Jojo::makepassword();
                /* Save new password to DB. Clear old reminder. Clear reset code. Display password on screen. */
                Jojo::updateQuery("UPDATE {user} SET us_password = ?, us_salt='', us_reminder='', us_reset='' WHERE userid = ? LIMIT 1", array(sha1($newpassword), $userid));
                $messages[] = "Your password has been reset to <b>$newpassword</b>";
                $smarty->assign('changed', true);
                $smarty->assign('newpassword', $newpassword);
            }

        /* Email address / username has been entered */
        } elseif ($search != '') {
            $users = Jojo::selectQuery("SELECT userid, us_email, us_login, us_reminder FROM {user} WHERE us_email = ? OR us_login = ?", array($search, $search));

            if (!count($users)) {
                $errors[] = 'There is no user in our system with email address or username: '.$search;
            }
            
            foreach ($users as $user) {
                /* ensure we have an email address */
                $email = $user['us_email'];
    
    
                if (($type == 'reminder') && ($user['us_reminder'] == '')) {
                    $action = 'reset';
                    $messages[] = 'There is no password reminder for this account - sending password reset link instead.';
                } else  {
                    $action = $type;
                }
                
    
                if (empty($email) && !count($errors)) {
                    $errors[] = 'There is no email address stored against this user account, so the password is unable to be reset. Please contact the webmaster ('._FROMADDRESS.') to manually reset your password.';
                } elseif ($action == 'reminder') {
                    /* Send reminder email */
                    $reminder = $user['us_reminder'];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -55,7 +55,7 @@
             $users = Jojo::selectQuery("SELECT userid, us_email, us_login, us_reminder FROM {user} WHERE us_email = ? OR us_login = ?", array($search, $search));
 
             if (!count($users)) {
-                $errors[] = 'There is no user in our system with email address or username: '.$search;
+                $errors[] = 'There is no user in our system with email address or username: '.htmlentities($search);
             }
             
             foreach ($users as $user) {
```
