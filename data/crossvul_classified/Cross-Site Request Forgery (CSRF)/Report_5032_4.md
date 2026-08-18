# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 5032_4
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5032_4`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 796-836 of the vulnerable file.

                $par  = $key[0] == '_' ? $key : '_'.$key;
                $url .= $delm.urlencode($par).'='.urlencode($val);
                $delm = '&';
            }
        }

        $base_path = strval($_SERVER['REDIRECT_SCRIPT_URL'] ?: $_SERVER['SCRIPT_NAME']);
        $base_path = preg_replace('![^/]+$!', '', $base_path);

        if ($secure && ($token = $this->get_secure_url_token(true))) {
            // add token to the url
            $url = $token . '/' . $url;

            // remove old token from the path
            $base_path = rtrim($base_path, '/');
            $base_path = preg_replace('/\/[a-f0-9]{' . strlen($token) . '}$/', '', $base_path);

            // this need to be full url to make redirects work
            $absolute = true;
        }

        if ($absolute || $full) {
            // add base path to this Roundcube installation
            if ($base_path == '') $base_path = '/';
            $prefix = $base_path;

            // prepend protocol://hostname:port
            if ($full) {
                $prefix = rcube_utils::resolve_url($prefix);
            }

            $prefix = rtrim($prefix, '/') . '/';
        }
        else {
            $prefix = './';
        }

        return $prefix . $url;
    }

    /**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -813,6 +813,8 @@
             // this need to be full url to make redirects work
             $absolute = true;
         }
+        else if ($secure && ($token = $this->get_request_token()))
+            $url .= $delm . '_token=' . urlencode($token);
 
         if ($absolute || $full) {
             // add base path to this Roundcube installation
```
