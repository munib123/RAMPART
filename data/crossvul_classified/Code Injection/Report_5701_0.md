# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 5701_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5701_0`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 255-295 of the vulnerable file.


// Generate filename and mime type if needed
if ($asfile) {
    $pma_uri_parts = parse_url($cfg['PmaAbsoluteUri']);
    if ($export_type == 'server') {
        if (isset($remember_template)) {
            $GLOBALS['PMA_Config']->setUserValue('pma_server_filename_template',
                'Export/file_template_server', $filename_template);
        }
    } elseif ($export_type == 'database') {
        if (isset($remember_template)) {
            $GLOBALS['PMA_Config']->setUserValue('pma_db_filename_template',
                'Export/file_template_database', $filename_template);
        }
    } else {
        if (isset($remember_template)) {
            $GLOBALS['PMA_Config']->setUserValue('pma_table_filename_template',
                'Export/file_template_table', $filename_template);
        }
    }
    $filename = PMA_expandUserString($filename_template);
    $filename = PMA_sanitize_filename($filename);

    // Grab basic dump extension and mime type
    // Check if the user already added extension; get the substring where the extension would be if it was included
    $extension_start_pos = strlen($filename) - strlen($export_list[$type]['extension']) - 1;
    $user_extension = substr($filename, $extension_start_pos, strlen($filename));
    $required_extension = "." . $export_list[$type]['extension'];
    if (strtolower($user_extension) != $required_extension) {
        $filename  .= $required_extension;
    }
    $mime_type  = $export_list[$type]['mime_type'];

    // If dump is going to be compressed, set correct mime_type and add
    // compression to extension
    if ($compression == 'bzip2') {
        $filename  .= '.bz2';
        $mime_type = 'application/x-bzip2';
    } elseif ($compression == 'gzip') {
        $filename  .= '.gz';
        $mime_type = 'application/x-gzip';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -272,6 +272,8 @@
                 'Export/file_template_table', $filename_template);
         }
     }
+    // remove dots in template to avoid a remote code execution vulnerability
+    $filename_template = str_replace('.', '', $filename_template);
     $filename = PMA_expandUserString($filename_template);
     $filename = PMA_sanitize_filename($filename);
 
```
