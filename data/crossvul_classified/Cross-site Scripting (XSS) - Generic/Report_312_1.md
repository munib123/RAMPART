# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 312_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `312_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 2240-2280 of the vulnerable file.

                isset($message) ? $message : null,
                isset($sql_data) ? $sql_data : null,
                $displayResultsObject,
                $pmaThemeImage,
                $unlim_num_rows,
                $num_rows,
                isset($disp_query) ? $disp_query : null,
                isset($disp_message) ? $disp_message : null,
                $profiling_results,
                isset($query_type) ? $query_type : null,
                isset($selectedTables) ? $selectedTables : null,
                $sql_query,
                isset($complete_query) ? $complete_query : null
            );
        }

        // Handle disable/enable foreign key checks
        Util::handleDisableFKCheckCleanup($default_fk_check);

        foreach ($warning_messages as $warning) {
            $message = Message::notice($warning);
            $html_output .= $message->getDisplay();
        }

        return $html_output;
    }

    /**
     * Function to define pos to display a row
     *
     * @param int $number_of_line Number of the line to display
     * @param int $max_rows       Number of rows by page
     *
     * @return int Start position to display the line
     */
    private function getStartPosToDisplayRow($number_of_line, $max_rows = null)
    {
        if (null === $max_rows) {
            $max_rows = $_SESSION['tmpval']['max_rows'];
        }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2257,7 +2257,7 @@
         Util::handleDisableFKCheckCleanup($default_fk_check);
 
         foreach ($warning_messages as $warning) {
-            $message = Message::notice($warning);
+            $message = Message::notice(Message::sanitize($warning));
             $html_output .= $message->getDisplay();
         }
 
```
