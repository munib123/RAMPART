# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 2370_4
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2370_4`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 597-637 of the vulnerable file.

                $scheme = 'http';
                break;
            case 'rejected':
                $scheme = 'http';
                break;
        }

        return $scheme;
    }

    /**
     * Write log entry
     *
     * @param string $local_path
     * @param string $remote_path
     * @param string $error
     * @return bool|int
     */
    function _log($local_path, $remote_path, $error) {
        $data = sprintf("[%s] [%s => %s] %s\n", date('r'), $local_path, $remote_path, $error);

        $filename = w3_debug_log('cdn');

        return @file_put_contents($filename, $data, FILE_APPEND);
    }

    /**
     * Our error handler
     *
     * @param integer $errno
     * @param string $errstr
     * @return boolean
     */
    function _error_handler($errno, $errstr) {
        $this->_last_error = $errstr;

        return false;
    }

    /**
     * Returns last error
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -614,6 +614,7 @@
      */
     function _log($local_path, $remote_path, $error) {
         $data = sprintf("[%s] [%s => %s] %s\n", date('r'), $local_path, $remote_path, $error);
+        $data = strtr($data, '<>', '..');
 
         $filename = w3_debug_log('cdn');
 
```
