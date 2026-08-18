# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2082_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2082_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 551-591 of the vulnerable file.

} elseif ($bookmark_created) {
    $special_message = '[br]'  . sprintf(
        __('Bookmark %s created'),
        htmlspecialchars($bkm_label)
    );
} elseif ($finished && ! $error) {
    if ($import_type == 'query') {
        $message = PMA_Message::success();
    } else {
        $message = PMA_Message::success(
            '<em>'
            . __('Import has been successfully finished, %d queries executed.')
            . '</em>'
        );
        $message->addParam($executed_queries);

        if ($import_notice) {
            $message->addString($import_notice);
        }
        if (isset($local_import_file)) {
            $message->addString('(' . $local_import_file . ')');
        } else {
            $message->addString('(' . $_FILES['import_file']['name'] . ')');
        }
    }
}

// Did we hit timeout? Tell it user.
if ($timeout_passed) {
    $message = PMA_Message::error(
        __('Script timeout passed, if you want to finish import, please resubmit same file and import will resume.')
    );
    if ($offset == 0 || (isset($original_skip) && $original_skip == $offset)) {
        $message->addString(
            __('However on last run no data has been parsed, this usually means phpMyAdmin won\'t be able to finish this import unless you increase php time limits.')
        );
    }
}

// if there is any message, copy it into $_SESSION as well,
// so we can obtain it by AJAX call
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -568,9 +568,9 @@
             $message->addString($import_notice);
         }
         if (isset($local_import_file)) {
-            $message->addString('(' . $local_import_file . ')');
+            $message->addString('(' . htmlspecialchars($local_import_file) . ')');
         } else {
-            $message->addString('(' . $_FILES['import_file']['name'] . ')');
+            $message->addString('(' . htmlspecialchars($_FILES['import_file']['name']) . ')');
         }
     }
 }
```
