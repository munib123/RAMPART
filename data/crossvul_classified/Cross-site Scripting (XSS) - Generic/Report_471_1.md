# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 471_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `471_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 25-65 of the vulnerable file.

 *      \ingroup    member
 *      \brief      Member's type setup
 */

require '../main.inc.php';
require_once DOL_DOCUMENT_ROOT.'/core/lib/member.lib.php';
require_once DOL_DOCUMENT_ROOT.'/adherents/class/adherent.class.php';
require_once DOL_DOCUMENT_ROOT.'/adherents/class/adherent_type.class.php';
require_once DOL_DOCUMENT_ROOT.'/core/class/extrafields.class.php';

$langs->load("members");

$rowid  = GETPOST('rowid','int');
$action = GETPOST('action','alpha');
$cancel = GETPOST('cancel','alpha');
$backtopage = GETPOST('backtopage','alpha');

$search_lastname	= GETPOST('search_lastname','alpha');
$search_login		= GETPOST('search_login','alpha');
$search_email		= GETPOST('search_email','alpha');
$type				= GETPOST('type','alpha');
$status				= GETPOST('status','alpha');

$limit = GETPOST('limit','int')?GETPOST('limit','int'):$conf->liste_limit;
$sortfield = GETPOST("sortfield",'alpha');
$sortorder = GETPOST("sortorder",'alpha');
$page = GETPOST("page",'int');
if (empty($page) || $page == -1) { $page = 0; }     // If $page is not defined, or '' or -1
$offset = $limit * $page ;
$pageprev = $page - 1;
$pagenext = $page + 1;
if (! $sortorder) {  $sortorder="DESC"; }
if (! $sortfield) {  $sortfield="d.lastname"; }

$label=GETPOST("label","alpha");
$subscription=GETPOST("subscription","int");
$vote=GETPOST("vote","int");
$comment=GETPOST("comment");
$mail_valid=GETPOST("mail_valid");

// Security check
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,7 +42,7 @@
 $search_lastname	= GETPOST('search_lastname','alpha');
 $search_login		= GETPOST('search_login','alpha');
 $search_email		= GETPOST('search_email','alpha');
-$type				= GETPOST('type','alpha');
+$type				= GETPOST('type','intcomma');
 $status				= GETPOST('status','alpha');
 
 $limit = GETPOST('limit','int')?GETPOST('limit','int'):$conf->liste_limit;
@@ -59,8 +59,8 @@
 $label=GETPOST("label","alpha");
 $subscription=GETPOST("subscription","int");
 $vote=GETPOST("vote","int");
-$comment=GETPOST("comment");
-$mail_valid=GETPOST("mail_valid");
+$comment=GETPOST("comment",'alphanohtml');
+$mail_valid=GETPOST("mail_valid",'none');
 
 // Security check
 $result=restrictedArea($user,'adherent',$rowid,'adherent_type');
```
