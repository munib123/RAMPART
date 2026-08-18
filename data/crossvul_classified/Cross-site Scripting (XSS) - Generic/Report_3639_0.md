# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3639_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3639_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1419-1459 of the vulnerable file.

    <div id="draft__status"><?php if(!empty($INFO['draft'])) echo $lang['draftdate'].' '.dformat();?></div>
    <div id="tool__bar"><?php if ($wr && $data['media_manager']){?><a href="<?php echo DOKU_BASE?>lib/exe/mediamanager.php?ns=<?php echo $INFO['namespace']?>"
        target="_blank"><?php echo $lang['mediaselect'] ?></a><?php }?></div>

    </div>
    <?php

    html_form('edit', $form);
    print '</div>'.NL;
}

/**
 * Display the default edit form
 *
 * Is the default action for HTML_EDIT_FORMSELECTION.
 */
function html_edit_form($param) {
    global $TEXT;

    if ($param['target'] !== 'section') {
        msg('No editor for edit target ' . $param['target'] . ' found.', -1);
    }

    $attr = array('tabindex'=>'1');
    if (!$param['wr']) $attr['readonly'] = 'readonly';

    $param['form']->addElement(form_makeWikiText($TEXT, $attr));
}

/**
 * Adds a checkbox for minor edits for logged in users
 *
 * @author Andreas Gohr <andi@splitbrain.org>
 */
function html_minoredit(){
    global $conf;
    global $lang;
    // minor edits are for logged in users only
    if(!$conf['useacl'] || !$_SERVER['REMOTE_USER']){
        return false;
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1436,7 +1436,7 @@
     global $TEXT;
 
     if ($param['target'] !== 'section') {
-        msg('No editor for edit target ' . $param['target'] . ' found.', -1);
+        msg('No editor for edit target ' . hsc($param['target']) . ' found.', -1);
     }
 
     $attr = array('tabindex'=>'1');
```
