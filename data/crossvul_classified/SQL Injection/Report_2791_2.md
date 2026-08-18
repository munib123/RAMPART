# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2791_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2791_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 87-127 of the vulnerable file.

}

/*
 * View
 */

$form = new Form($db);
if (! empty($conf->projet->enabled)) { $formproject = new FormProjets($db); }

$title = $langs->trans('Donation') . " - " . $langs->trans('Documents');
$helpurl = "";
llxHeader('', $title, $helpurl);


if ($object->id)
{
	$object->fetch_thirdparty();

	$head=donation_prepare_head($object);

	dol_fiche_head($head, 'documents',  $langs->trans("Donation"), 0, 'generic');


	// Construit liste des fichiers
	$filearray=dol_dir_list($upload_dir,"files",0,'','(\.meta|_preview.*\.png)$',$sortfield,(strtolower($sortorder)=='desc'?SORT_DESC:SORT_ASC),1);
	$totalsize=0;
	foreach($filearray as $key => $file)
	{
		$totalsize+=$file['size'];
	}

	$linkback = '<a href="'.DOL_URL_ROOT.'/don/list.php'.(! empty($socid)?'?socid='.$socid:'').'">'.$langs->trans("BackToList").'</a>';
	
	$morehtmlref='<div class="refidno">';
	// Project
	if (! empty($conf->projet->enabled))
	{
	    $langs->load("projects");
	    $morehtmlref.=$langs->trans('Project') . ' ';
	    if ($user->rights->don->creer)
	    {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -104,7 +104,7 @@
 
 	$head=donation_prepare_head($object);
 
-	dol_fiche_head($head, 'documents',  $langs->trans("Donation"), 0, 'generic');
+	dol_fiche_head($head, 'documents',  $langs->trans("Donation"), -1, 'generic');
 
 
 	// Construit liste des fichiers
@@ -116,7 +116,7 @@
 	}
 
 	$linkback = '<a href="'.DOL_URL_ROOT.'/don/list.php'.(! empty($socid)?'?socid='.$socid:'').'">'.$langs->trans("BackToList").'</a>';
-	
+
 	$morehtmlref='<div class="refidno">';
 	// Project
 	if (! empty($conf->projet->enabled))
@@ -151,13 +151,13 @@
 	    }
 	}
 	$morehtmlref.='</div>';
-	
-	
+
+
 	dol_banner_tab($object, 'rowid', $linkback, 1, 'rowid', 'ref', $morehtmlref);
-	
+
 	print '<div class="fichecenter">';
 	print '<div class="underbanner clearboth"></div>';
-	
+
     print '<table class="border" width="100%">';
 
 	// Ref
@@ -166,7 +166,7 @@
 	print $form->showrefnav($object, 'id', $linkback, 1, 'rowid', 'ref', '');
 	print '</td></tr>';
     */
-    
+
 	// Societe
 	//print "<tr><td>".$langs->trans("Company")."</td><td>".$object->client->getNomUrl(1)."</td></tr>";
 
@@ -175,9 +175,9 @@
     print '</table>';
 
     print '</div>';
-    
+
     print '<div class="clearboth"></div>';
-    
+
     dol_fiche_end();
 
     $modulepart = 'don';
```
