# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2418_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2418_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 371-411 of the vulnerable file.

            }

            /* Not account expired or password forced change go to main page */
            new log("security","login","",array(),"User \"$username\" logged in successfully") ;
            $plist= new pluglist($config, $ui);

            stats::log('global', 'global', array(),  $action = 'login', $amount = 1, 0);

            if(isset($plug) && isset($plist->dirlist[$plug])) {
                header ("Location: main.php?plug=".$plug."&amp;global_check=1");
            }else{
                header ("Location: main.php?global_check=1");
            }
            exit;
        }
    }
}

/* Fill template with required values */
$smarty->assign ('date', gmdate("D, d M Y H:i:s"));
$smarty->assign ('username', $username);
$smarty->assign ('personal_img', get_template_path('images/login-head.png'));
$smarty->assign ('password_img', get_template_path('images/password.png'));
$smarty->assign ('directory_img', get_template_path('images/ldapserver.png'));

/* Some error to display? */
if (!isset($message)) {
    $message= "";
}

$smarty->assign ("message", $message);

/* Generate server list */
$servers= array();
if (isset($_POST['server'])){
    $selected= get_post('server');
} else {
    $selected= $config->data['MAIN']['DEFAULT'];
}
foreach ($config->data['LOCATIONS'] as $key => $ignored) {
    $servers[$key]= $key;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -388,7 +388,7 @@
 
 /* Fill template with required values */
 $smarty->assign ('date', gmdate("D, d M Y H:i:s"));
-$smarty->assign ('username', $username);
+$smarty->assign ('username', set_post($username));
 $smarty->assign ('personal_img', get_template_path('images/login-head.png'));
 $smarty->assign ('password_img', get_template_path('images/password.png'));
 $smarty->assign ('directory_img', get_template_path('images/ldapserver.png'));
```
