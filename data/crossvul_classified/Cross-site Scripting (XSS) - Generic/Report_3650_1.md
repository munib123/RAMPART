# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3650_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3650_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 276-310 of the vulnerable file.


        $media['case'] = 'default';
        $add_url = '';
        if (!empty($serendipity['GET']['htmltarget'])) {
            $add_url .= '&amp;serendipity[htmltarget]=' . htmlspecialchars($serendipity['GET']['htmltarget']);
        }

        if (!empty($serendipity['GET']['filename_only'])) {
            $add_url .= '&amp;serendipity[filename_only]=' . htmlspecialchars($serendipity['GET']['filename_only']);
        }

        if (!isset($serendipity['thumbPerPage2'])) {
            $serendipity['thumbPerPage2'] = 3;
        }

        ob_start();
        $block = serendipity_displayImageList(
          isset($serendipity['GET']['page'])   ? $serendipity['GET']['page']   : 1,
          $serendipity['thumbPerPage2'],
          ($serendipity['showMediaToolbar'] ? true : false),
          '?serendipity[step]=1' . $add_url . '&amp;serendipity[textarea]='. $serendipity['GET']['textarea'],
          true,
          null,
          false
        );
        $media['external'] = ob_get_contents();
        ob_end_clean();
        serendipity_smarty_fetch('MEDIA_LIST', $block);
}

$media = array_merge($serendipity['GET'], $media);
$serendipity['smarty']->assign_by_ref('media', $media);
$serendipity['smarty']->display(serendipity_getTemplateFile($showFile, 'serendipityPath'));

/* vim: set sts=4 ts=4 expandtab : */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -293,7 +293,7 @@
           isset($serendipity['GET']['page'])   ? $serendipity['GET']['page']   : 1,
           $serendipity['thumbPerPage2'],
           ($serendipity['showMediaToolbar'] ? true : false),
-          '?serendipity[step]=1' . $add_url . '&amp;serendipity[textarea]='. $serendipity['GET']['textarea'],
+          '?serendipity[step]=1' . $add_url . '&amp;serendipity[textarea]='. htmlspecialchars($serendipity['GET']['textarea']),
           true,
           null,
           false
```
