# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3251_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3251_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 306-346 of the vulnerable file.

            'end' => $end,
            'args' => $args,
        ]);
    }

    /**
     * Renders the global variables of the request.
     * List of global variables is defined in [[displayVars]].
     * @return string the rendering result
     * @see displayVars
     */
    public function renderRequest()
    {
        $request = '';
        foreach ($this->displayVars as $name) {
            if (!empty($GLOBALS[$name])) {
                $request .= '$' . $name . ' = ' . VarDumper::export($GLOBALS[$name]) . ";\n\n";
            }
        }

        return '<pre>' . rtrim($request, "\n") . '</pre>';
    }

    /**
     * Determines whether given name of the file belongs to the framework.
     * @param string $file name to be checked.
     * @return bool whether given name of the file belongs to the framework.
     */
    public function isCoreFile($file)
    {
        return $file === null || strpos(realpath($file), YII2_PATH . DIRECTORY_SEPARATOR) === 0;
    }

    /**
     * Creates HTML containing link to the page with the information on given HTTP status code.
     * @param int $statusCode to be used to generate information link.
     * @param string $statusDescription Description to display after the the status code.
     * @return string generated HTML with HTTP status code information.
     */
    public function createHttpStatusLink($statusCode, $statusDescription)
    {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -323,7 +323,7 @@
             }
         }
 
-        return '<pre>' . rtrim($request, "\n") . '</pre>';
+        return '<pre>' . $this->htmlEncode(rtrim($request, "\n")) . '</pre>';
     }
 
     /**
```
