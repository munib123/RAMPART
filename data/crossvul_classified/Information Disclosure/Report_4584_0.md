# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 4584_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4584_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 242-282 of the vulnerable file.

                if (file_exists($path . $if)) {
                    $path .= $if;
                    break;
                }
            }
        }

        if (is_dir($path)) {
            /* Path is a directory - maybe no index file was found in the previous step, or maybe the path didn't end
             * with a slash. Either way, we don't do directory listings.
             */
            throw new Error\NotFound('Directory listing not available.');
        }

        if (!file_exists($path)) {
            // file not found
            Logger::info('Could not find file \'' . $path . '\'.');
            throw new Error\NotFound('The URL wasn\'t found in the module.');
        }

        if (substr($path, -4) === '.php') {
            // PHP file - attempt to run it

            /* In some environments, $_SERVER['SCRIPT_NAME'] is already set with $_SERVER['PATH_INFO']. Check for that
             * case, and append script name only if necessary.
             *
             * Contributed by Travis Hegner.
             */
            $script = "/$module/$url";
            if (strpos($request->getScriptName(), $script) === false) {
                $request->server->set('SCRIPT_NAME', $request->getScriptName() . '/' . $module . '/' . $url);
            }

            require($path);
            exit();
        }

        // some other file type - attempt to serve it

        // find MIME type for file, based on extension
        $contentType = null;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -259,7 +259,7 @@
             throw new Error\NotFound('The URL wasn\'t found in the module.');
         }
 
-        if (substr($path, -4) === '.php') {
+        if (mb_strtolower(substr($path, -4), 'UTF-8') === '.php') {
             // PHP file - attempt to run it
 
             /* In some environments, $_SERVER['SCRIPT_NAME'] is already set with $_SERVER['PATH_INFO']. Check for that
```
