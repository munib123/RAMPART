# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 3613_7
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3613_7`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 30-71 of the vulnerable file.

 *  MEMBER_URL_REDIRECT_SUBSCRIPTION    Url to redirect once subscribe submitted
 *  MEMBER_NEWFORM_FORCETYPE            Force type of member
 *  MEMBER_NEWFORM_FORCEMORPHY          Force nature of member (mor/phy)
 *  MEMBER_NEWFORM_FORCECOUNTRYCODE     Force country
 */

define("NOLOGIN",1);		// This means this output page does not require to be logged.
define("NOCSRFCHECK",1);	// We accept to go on this page from external web site.

require("../../main.inc.php");
require_once(DOL_DOCUMENT_ROOT."/adherents/class/adherent.class.php");
require_once(DOL_DOCUMENT_ROOT."/adherents/class/adherent_type.class.php");
require_once(DOL_DOCUMENT_ROOT."/core/class/extrafields.class.php");
require_once(DOL_DOCUMENT_ROOT."/core/class/html.formcompany.class.php");
require_once(DOL_DOCUMENT_ROOT."/core/lib/company.lib.php");

// Init vars
$errmsg='';
$num=0;
$error=0;
$backtopage=GETPOST('backtopage');
$action=GETPOST('action');

// Load translation files
$langs->load("main");
$langs->load("members");
$langs->load("companies");
$langs->load("install");
$langs->load("other");

// Security check
if (empty($conf->adherent->enabled)) accessforbidden('',1,1,1);

if (empty($conf->global->MEMBER_ENABLE_PUBLIC))
{
    print $langs->trans("Auto subscription form for public visitors has no been enabled");
    exit;
}


/**
 * Show header for new member
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -47,8 +47,8 @@
 $errmsg='';
 $num=0;
 $error=0;
-$backtopage=GETPOST('backtopage');
-$action=GETPOST('action');
+$backtopage=GETPOST('backtopage','alpha');
+$action=GETPOST('action','alpha');
 
 // Load translation files
 $langs->load("main");
@@ -255,7 +255,7 @@
                 $result=$adh->send_an_email($conf->global->ADHERENT_AUTOREGISTER_MAIL,$conf->global->ADHERENT_AUTOREGISTER_MAIL_SUBJECT,array(),array(),array(),"","",0,-1);
             }
 
-            if ($backtopage) $urlback=$backtopage;
+            if (! empty($backtopage)) $urlback=$backtopage;
             else if ($conf->global->MEMBER_URL_REDIRECT_SUBSCRIPTION)
             {
                 $urlback=$conf->global->MEMBER_URL_REDIRECT_SUBSCRIPTION;
@@ -545,7 +545,7 @@
 // Save
 print '<br><center>';
 print '<input type="submit" value="'.$langs->trans("Save").'" id="submitsave" class="button">';
-if ($backtopage)
+if (! empty($backtopage))
 {
     print ' &nbsp; &nbsp; <input type="submit" value="'.$langs->trans("Cancel").'" id="submitcancel" class="button">';
 }
```
