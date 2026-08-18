# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2790_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2790_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 93-133 of the vulnerable file.

if (GETPOST('type','alpha')) $type=GETPOST('type','alpha');
else $type=dol_mimetype($original_file);

// Define attachment (attachment=true to force choice popup 'open'/'save as')
$attachment = true;
if (preg_match('/\.(html|htm)$/i',$original_file)) $attachment = false;
if (isset($_GET["attachment"])) $attachment = GETPOST("attachment",'alpha')?true:false;
if (! empty($conf->global->MAIN_DISABLE_FORCE_SAVEAS)) $attachment=false;

// Security: Delete string ../ into $original_file
$original_file = str_replace("../","/", $original_file);

// Find the subdirectory name as the reference
$refname=basename(dirname($original_file)."/");

// Security check
if (empty($modulepart)) accessforbidden('Bad value for parameter modulepart');
$check_access = dol_check_secure_access_document($modulepart, $original_file, $entity, $refname);
$accessallowed              = $check_access['accessallowed'];
$sqlprotectagainstexternals = $check_access['sqlprotectagainstexternals'];
$original_file              = $check_access['original_file'];               // original_file is now a full path name

// Basic protection (against external users only)
if ($user->societe_id > 0)
{
	if ($sqlprotectagainstexternals)
	{
		$resql = $db->query($sqlprotectagainstexternals);
		if ($resql)
		{
			$num=$db->num_rows($resql);
			$i=0;
			while ($i < $num)
			{
				$obj = $db->fetch_object($resql);
				if ($user->societe_id != $obj->fk_soc)
				{
					$accessallowed=0;
					break;
				}
				$i++;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -110,7 +110,7 @@
 $check_access = dol_check_secure_access_document($modulepart, $original_file, $entity, $refname);
 $accessallowed              = $check_access['accessallowed'];
 $sqlprotectagainstexternals = $check_access['sqlprotectagainstexternals'];
-$original_file              = $check_access['original_file'];               // original_file is now a full path name
+$fullpath_original_file     = $check_access['original_file'];               // $fullpath_original_file is now a full path name
 
 // Basic protection (against external users only)
 if ($user->societe_id > 0)
@@ -137,36 +137,35 @@
 }
 
 // Security:
-// Limite acces si droits non corrects
+// Limit access if permissions are wrong
 if (! $accessallowed)
 {
 	accessforbidden();
 }
 
 // Security:
-// On interdit les remontees de repertoire ainsi que les pipe dans
-// les noms de fichiers.
-if (preg_match('/\.\./',$original_file) || preg_match('/[<>|]/',$original_file))
+// On interdit les remontees de repertoire ainsi que les pipe dans les noms de fichiers.
+if (preg_match('/\.\./',$fullpath_original_file) || preg_match('/[<>|]/',$fullpath_original_file))
 {
-	dol_syslog("Refused to deliver file ".$original_file);
-	$file=basename($original_file);		// Do no show plain path of original_file in shown error message
-	dol_print_error(0,$langs->trans("ErrorFileNameInvalid",$file));
+	dol_syslog("Refused to deliver file ".$fullpath_original_file);
+	print "ErrorFileNameInvalid: ".$original_file;
 	exit;
 }
 
 
 clearstatcache();
 
-$filename = basename($original_file);
+$filename = basename($fullpath_original_file);
 
 // Output file on browser
-dol_syslog("document.php download $original_file $filename content-type=$type");
-$original_file_osencoded=dol_osencode($original_file);	// New file name encoded in OS encoding charset
+dol_syslog("document.php download $fullpath_original_file filename=$filename content-type=$type");
+$fullpath_original_file_osencoded=dol_osencode($fullpath_original_file);	// New file name encoded in OS encoding charset
 
 // This test if file exists should be useless. We keep it to find bug more easily
-if (! file_exists($original_file_osencoded))
+if (! file_exists($fullpath_original_file_osencoded))
 {
-	dol_print_error(0,$langs->trans("ErrorFileDoesNotExists",$original_file));
+	dol_syslog("ErrorFileDoesNotExists: ".$fullpath_original_file);
+	print "ErrorFileDoesNotExists: ".$original_file;
 	exit;
 }
 
@@ -177,7 +176,7 @@
 // Add MIME Content-Disposition from RFC 2183 (inline=automatically displayed, atachment=need user action to open)
 if ($attachment) header('Content-Disposition: attachment; filename="'.$filename.'"');
 else header('Content-Disposition: inline; filename="'.$filename.'"');
-header('Content-Length: ' . dol_filesize($original_file));
+header('Content-Length: ' . dol_filesize($fullpath_original_file));
 // Ajout directives pour resoudre bug IE
 header('Cache-Control: Public, must-revalidate');
 header('Pragma: public');
@@ -185,6 +184,6 @@
 //ob_clean();
 //flush();
 
-readfile($original_file_osencoded);
+readfile($fullpath_original_file_osencoded);
 
 if (is_object($db)) $db->close();
```
