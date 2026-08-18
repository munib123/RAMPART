# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5712_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5712_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 97-137 of the vulnerable file.

        } else {
            $response = PMA_Response::getInstance();
            $response->addJSON(
                'message',
                PMA_Util::getMessage(
                    PMA_Message::success(), $sql_query
                )
            );
        }
        
        exit;
        
    } else {
        if ($GLOBALS['is_ajax_request'] != true) {
            $message = PMA_Message::rawError(PMA_DBI_getError());
        } else {
            $response = PMA_Response::getInstance();
            $response->addJSON(
                'message',
                PMA_Message::error(
                    "<i>$sql_query</i><br /><br />" . PMA_DBI_getError()
                )
            );
            $response->isSuccess(false);
            exit;
        }
    }
}

// prefill values if not already filled from former submission
$view = array(
    'or_replace' => '',
    'algorithm' => '',
    'name' => '',
    'column_names' => '',
    'as' => $sql_query,
    'with' => array(),
);

if (PMA_isValid($_REQUEST['view'], 'array')) {
    $view = array_merge($view, $_REQUEST['view']);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -114,7 +114,8 @@
             $response->addJSON(
                 'message',
                 PMA_Message::error(
-                    "<i>$sql_query</i><br /><br />" . PMA_DBI_getError()
+                    "<i>" . htmlspecialchars($sql_query) . "</i><br /><br />"
+                    . PMA_DBI_getError()
                 )
             );
             $response->isSuccess(false);
```
