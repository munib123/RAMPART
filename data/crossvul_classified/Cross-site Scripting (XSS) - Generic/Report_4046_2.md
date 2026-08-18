# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4046_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4046_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1806-1846 of the vulnerable file.

    {
        static $username;

        // alread fetched
        if (!empty($username)) {
            return $username;
        }

        // Current username is an e-mail address
        if (strpos($_SESSION['username'], '@')) {
            $username = $_SESSION['username'];
        }
        // get e-mail address from default identity
        else if ($sql_arr = $this->app->user->get_identity()) {
            $username = $sql_arr['email'];
        }
        else {
            $username = $this->app->user->get_username();
        }

        return rcube_utils::idn_to_utf8($username);
    }

    /**
     * GUI object 'loginform'
     * Returns code for the webmail login form
     *
     * @param array $attrib Named parameters
     *
     * @return string HTML code for the gui object
     */
    protected function login_form($attrib)
    {
        $default_host = $this->config->get('default_host');
        $autocomplete = (int) $this->config->get('login_autocomplete');

        $_SESSION['temp'] = true;

        // save original url
        $url = rcube_utils::get_input_value('_url', rcube_utils::INPUT_POST);
        if (empty($url) && !preg_match('/_(task|action)=logout/', $_SERVER['QUERY_STRING']))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1823,7 +1823,9 @@
             $username = $this->app->user->get_username();
         }
 
-        return rcube_utils::idn_to_utf8($username);
+        $username = rcube_utils::idn_to_utf8($username);
+
+        return html::quote($username);
     }
 
     /**
```
