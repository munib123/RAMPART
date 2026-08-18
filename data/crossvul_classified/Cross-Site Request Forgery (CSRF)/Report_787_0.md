# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 787_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `787_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 291-331 of the vulnerable file.

     *
     * @return array
     */
    protected function parseGeneral()
    {
        // Read the config and merge it. (note: We use temp variables to prevent
        // "Only variables should be passed by reference")
        $tempconfig = $this->parseConfigYaml('config.yml');
        $tempconfiglocal = $this->parseConfigYaml('config_local.yml');
        $general = Arr::replaceRecursive($tempconfig, $tempconfiglocal);

        // Merge the array with the defaults. Setting the required values that aren't already set.
        $general = Arr::replaceRecursive($this->defaultConfig, $general);

        if (isset($general['accept_file_types']) === true) {
            if (is_array($general['accept_file_types']) === false) {
                // Make sure old settings for 'accept_file_types' are not still picked up. Before 1.5.4 we used to store them
                // as a regex-like string, and we switched to an array. If we find the old style, fall back to the defaults.
                unset($general['accept_file_types']);
            }
            // accept uppercase and lowercase file extensions.
            $general['accept_file_types'] = array_values(
                array_unique(
                    array_merge(
                        $general['accept_file_types'],
                        array_map(function ($extension) {
                            return strtolower($extension);
                        }, $general['accept_file_types']),
                        array_map(function ($extension) {
                            return strtoupper($extension);
                        }, $general['accept_file_types'])
                    )
                )
            );
        }

        // Make sure Bolt's mount point is OK:
        $general['branding']['path'] = '/' . Str::makeSafe($general['branding']['path']);

        // Set the link in branding, if provided_by is set.
        $general['branding']['provided_link'] = Html::providerLink(
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -308,6 +308,10 @@
                 // as a regex-like string, and we switched to an array. If we find the old style, fall back to the defaults.
                 unset($general['accept_file_types']);
             }
+
+            // Just.. Say no to these.
+            $general['accept_file_types'] = array_diff($general['accept_file_types'], ['sh', 'asp', 'cgi', 'php', 'php3', 'ph3', 'php4', 'ph4', 'php5', 'ph5' ,'phtm', 'phtml']);
+
             // accept uppercase and lowercase file extensions.
             $general['accept_file_types'] = array_values(
                 array_unique(
```
