# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in php
**Pair ID:** 77_0
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `77_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```php
Lines 65-105 of the vulnerable file.

		dol_print_error($db);
	}
}

else if (preg_match('/del_(.*)/',$action,$reg))
{
	$code=$reg[1];
	if (dolibarr_del_const($db, $code, $conf->entity) > 0)
	{
		Header("Location: ".$_SERVER["PHP_SELF"]);
		exit;
	}
	else
	{
		dol_print_error($db);
	}
}

else if ($action == 'updateform')
{
	$res3=dolibarr_set_const($db, 'MAIN_UPLOAD_DOC',GETPOST('MAIN_UPLOAD_DOC','alpha'),'chaine',0,'',$conf->entity);
	$res4=dolibarr_set_const($db, "MAIN_UMASK", GETPOST('MAIN_UMASK','alpha'),'chaine',0,'',$conf->entity);
	$res5=dolibarr_set_const($db, "MAIN_ANTIVIRUS_COMMAND", trim(GETPOST('MAIN_ANTIVIRUS_COMMAND','none')),'chaine',0,'',$conf->entity);    // Use GETPOST none because we must accept "
	$res6=dolibarr_set_const($db, "MAIN_ANTIVIRUS_PARAM", trim(GETPOST('MAIN_ANTIVIRUS_PARAM','none')),'chaine',0,'',$conf->entity);	// Use GETPOST none because we must accept "
	if ($res3 && $res4 && $res5 && $res6) setEventMessages($langs->trans("RecordModifiedSuccessfully"), null, 'mesgs');
}



// Delete file
else if ($action == 'delete')
{
	$langs->load("other");
	$file = $conf->admin->dir_temp . '/' . GETPOST('urlfile');	// Do not use urldecode here ($_GET and $_REQUEST are already decoded by PHP).
	$ret=dol_delete_file($file);
	if ($ret) setEventMessages($langs->trans("FileWasRemoved", GETPOST('urlfile')), null, 'mesgs');
	else setEventMessages($langs->trans("ErrorFailToDeleteFile", GETPOST('urlfile')), null, 'errors');
	Header('Location: '.$_SERVER["PHP_SELF"]);
	exit;
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -82,10 +82,15 @@
 
 else if ($action == 'updateform')
 {
+	$antivircommand = GETPOST('MAIN_ANTIVIRUS_COMMAND','none');			// Use GETPOST none because we must accept ". Example c:\Progra~1\ClamWin\bin\clamscan.exe
+	$antivirparam = GETPOST('MAIN_ANTIVIRUS_PARAM','none');				// Use GETPOST none because we must accept ". Example --database="C:\Program Files (x86)\ClamWin\lib"
+	$antivircommand = dol_string_nospecial($antivircommand, '', array("|", ";", "<", ">", "&"));	// Sanitize command
+	$antivirparam = dol_string_nospecial($antivirparam, '', array("|", ";", "<", ">", "&"));		// Sanitize params
+
 	$res3=dolibarr_set_const($db, 'MAIN_UPLOAD_DOC',GETPOST('MAIN_UPLOAD_DOC','alpha'),'chaine',0,'',$conf->entity);
 	$res4=dolibarr_set_const($db, "MAIN_UMASK", GETPOST('MAIN_UMASK','alpha'),'chaine',0,'',$conf->entity);
-	$res5=dolibarr_set_const($db, "MAIN_ANTIVIRUS_COMMAND", trim(GETPOST('MAIN_ANTIVIRUS_COMMAND','none')),'chaine',0,'',$conf->entity);    // Use GETPOST none because we must accept "
-	$res6=dolibarr_set_const($db, "MAIN_ANTIVIRUS_PARAM", trim(GETPOST('MAIN_ANTIVIRUS_PARAM','none')),'chaine',0,'',$conf->entity);	// Use GETPOST none because we must accept "
+	$res5=dolibarr_set_const($db, "MAIN_ANTIVIRUS_COMMAND", trim($antivircommand),'chaine',0,'',$conf->entity);
+	$res6=dolibarr_set_const($db, "MAIN_ANTIVIRUS_PARAM", trim($antivirparam),'chaine',0,'',$conf->entity);
 	if ($res3 && $res4 && $res5 && $res6) setEventMessages($langs->trans("RecordModifiedSuccessfully"), null, 'mesgs');
 }
 
@@ -95,10 +100,10 @@
 else if ($action == 'delete')
 {
 	$langs->load("other");
-	$file = $conf->admin->dir_temp . '/' . GETPOST('urlfile');	// Do not use urldecode here ($_GET and $_REQUEST are already decoded by PHP).
+	$file = $conf->admin->dir_temp . '/' . GETPOST('urlfile','alpha');	// Do not use urldecode here ($_GET and $_REQUEST are already decoded by PHP).
 	$ret=dol_delete_file($file);
-	if ($ret) setEventMessages($langs->trans("FileWasRemoved", GETPOST('urlfile')), null, 'mesgs');
-	else setEventMessages($langs->trans("ErrorFailToDeleteFile", GETPOST('urlfile')), null, 'errors');
+	if ($ret) setEventMessages($langs->trans("FileWasRemoved", GETPOST('urlfile','alpha')), null, 'mesgs');
+	else setEventMessages($langs->trans("ErrorFailToDeleteFile", GETPOST('urlfile','alpha')), null, 'errors');
 	Header('Location: '.$_SERVER["PHP_SELF"]);
 	exit;
 }
```
