# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 64_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `64_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 31-71 of the vulnerable file.

            $mailtext = __('GREETINGS');
        }
        $mailtext .= __('PASSWORD_RESET_REQUEST',$_SERVER['HTTP_HOST'],$user,$rkey,$_SERVER['HTTP_HOST'],$user,$rkey);
        if (!empty($rkey)) send_email($to, $subject, $mailtext, $from);
        unset($output);
    }

    header("Location: /reset/?action=code&user=".$_POST['user']);
    exit;
}

if ((!empty($_POST['user'])) && (!empty($_POST['code'])) && (!empty($_POST['password'])) ) {
    if ( $_POST['password'] == $_POST['password_confirm'] ) {
        $v_user = escapeshellarg($_POST['user']);
        $user = $_POST['user'];
        $cmd="/usr/bin/sudo /usr/local/vesta/bin/v-list-user";
        exec ($cmd." ".$v_user." json", $output, $return_var);
        if ( $return_var == 0 ) {
            $data = json_decode(implode('', $output), true);
            $rkey = $data[$user]['RKEY'];
            if ($rkey == $_POST['code']) {
                $v_password = tempnam("/tmp","vst");
                $fp = fopen($v_password, "w");
                fwrite($fp, $_POST['password']."\n");
                fclose($fp);
                $cmd="/usr/bin/sudo /usr/local/vesta/bin/v-change-user-password";
                exec ($cmd." ".$v_user." ".$v_password, $output, $return_var);
                unlink($v_password);
                if ( $return_var > 0 ) {
                    $ERROR = "<a class=\"error\">".__('An internal error occurred')."</a>";
                } else {
                    $_SESSION['user'] = $_POST['user'];
                    header("Location: /");
                    exit;
                }
            } else {
                $ERROR = "<a class=\"error\">".__('Invalid username or code')."</a>";
            }
        } else {
            $ERROR = "<a class=\"error\">".__('Invalid username or code')."</a>";
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -48,7 +48,7 @@
         if ( $return_var == 0 ) {
             $data = json_decode(implode('', $output), true);
             $rkey = $data[$user]['RKEY'];
-            if ($rkey == $_POST['code']) {
+            if (hash_equals($rkey, $POST[‘code’])) {
                 $v_password = tempnam("/tmp","vst");
                 $fp = fopen($v_password, "w");
                 fwrite($fp, $_POST['password']."\n");
```
