# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4047_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4047_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 380-420 of the vulnerable file.

     */
    public function get($name, $def = null)
    {
        if (isset($this->prop[$name])) {
            $result = $this->prop[$name];
        }
        else {
            $result = $def;
        }

        $result = $this->getenv_default('ROUNDCUBE_' . strtoupper($name), $result);
        $rcube  = rcube::get_instance();

        if ($name == 'timezone') {
            if (empty($result) || $result == 'auto') {
                $result = $this->client_timezone();
            }
        }
        else if ($name == 'client_mimetypes') {
            if (!$result && !$def) {
                $result = 'text/plain,text/html,text/xml'
                    . ',image/jpeg,image/gif,image/png,image/bmp,image/tiff,image/webp'
                    . ',application/x-javascript,application/pdf,application/x-shockwave-flash';
            }
            if ($result && is_string($result)) {
                $result = explode(',', $result);
            }
        }

        $plugin = $rcube->plugins->exec_hook('config_get', array(
            'name' => $name, 'default' => $def, 'result' => $result));

        return $plugin['result'];
    }

    /**
     * Setter for a config parameter
     *
     * @param string $name  Parameter name
     * @param mixed  $value Parameter value
     */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -397,7 +397,7 @@
         }
         else if ($name == 'client_mimetypes') {
             if (!$result && !$def) {
-                $result = 'text/plain,text/html,text/xml'
+                $result = 'text/plain,text/html'
                     . ',image/jpeg,image/gif,image/png,image/bmp,image/tiff,image/webp'
                     . ',application/x-javascript,application/pdf,application/x-shockwave-flash';
             }
```
