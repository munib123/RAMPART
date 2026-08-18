# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2790_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2790_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 32-72 of the vulnerable file.

require_once DOL_DOCUMENT_ROOT.'/core/lib/date.lib.php';
require_once DOL_DOCUMENT_ROOT.'/core/lib/images.lib.php';
require_once DOL_DOCUMENT_ROOT.'/core/lib/files.lib.php';
require_once DOL_DOCUMENT_ROOT.'/core/lib/functions2.lib.php';
require_once DOL_DOCUMENT_ROOT.'/core/class/html.formother.class.php';
require_once DOL_DOCUMENT_ROOT.'/core/class/html.formcompany.class.php';

$action=GETPOST('action','aZ09');

$langs->load("admin");
$langs->load("companies");

if (! $user->admin) accessforbidden();

$error=0;

/*
 * Actions
 */

if ( ($action == 'update' && empty($_POST["cancel"]))
|| ($action == 'updateedit') )
{
	$tmparray=getCountry(GETPOST('country_id','int'),'all',$db,$langs,0);
	if (! empty($tmparray['id']))
	{
		$mysoc->country_id   =$tmparray['id'];
		$mysoc->country_code =$tmparray['code'];
		$mysoc->country_label=$tmparray['label'];

		$s=$mysoc->country_id.':'.$mysoc->country_code.':'.$mysoc->country_label;
		dolibarr_set_const($db, "MAIN_INFO_SOCIETE_COUNTRY", $s,'chaine',0,'',$conf->entity);
	}

	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_NOM",$_POST["nom"],'chaine',0,'',$conf->entity);
	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_ADDRESS",$_POST["address"],'chaine',0,'',$conf->entity);
	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_TOWN",$_POST["town"],'chaine',0,'',$conf->entity);
	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_ZIP",$_POST["zipcode"],'chaine',0,'',$conf->entity);
	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_STATE",$_POST["state_id"],'chaine',0,'',$conf->entity);
	dolibarr_set_const($db, "MAIN_MONNAIE",$_POST["currency"],'chaine',0,'',$conf->entity);
	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_TEL",$_POST["tel"],'chaine',0,'',$conf->entity);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -49,7 +49,7 @@
  * Actions
  */
 
-if ( ($action == 'update' && empty($_POST["cancel"]))
+if ( ($action == 'update' && ! GETPOST("cancel",'alpha'))
 || ($action == 'updateedit') )
 {
 	$tmparray=getCountry(GETPOST('country_id','int'),'all',$db,$langs,0);
@@ -63,19 +63,19 @@
 		dolibarr_set_const($db, "MAIN_INFO_SOCIETE_COUNTRY", $s,'chaine',0,'',$conf->entity);
 	}
 
-	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_NOM",$_POST["nom"],'chaine',0,'',$conf->entity);
-	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_ADDRESS",$_POST["address"],'chaine',0,'',$conf->entity);
-	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_TOWN",$_POST["town"],'chaine',0,'',$conf->entity);
-	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_ZIP",$_POST["zipcode"],'chaine',0,'',$conf->entity);
-	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_STATE",$_POST["state_id"],'chaine',0,'',$conf->entity);
-	dolibarr_set_const($db, "MAIN_MONNAIE",$_POST["currency"],'chaine',0,'',$conf->entity);
-	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_TEL",$_POST["tel"],'chaine',0,'',$conf->entity);
-	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_FAX",$_POST["fax"],'chaine',0,'',$conf->entity);
-	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_MAIL",$_POST["mail"],'chaine',0,'',$conf->entity);
-	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_WEB",$_POST["web"],'chaine',0,'',$conf->entity);
-	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_NOTE",$_POST["note"],'chaine',0,'',$conf->entity);
-	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_GENCOD",$_POST["barcode"],'chaine',0,'',$conf->entity);
-	
+	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_NOM", GETPOST("nom",'nohtml'),'chaine',0,'',$conf->entity);
+	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_ADDRESS", GETPOST("address",'nohtml'),'chaine',0,'',$conf->entity);
+	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_TOWN", GETPOST("town",'nohtml'),'chaine',0,'',$conf->entity);
+	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_ZIP", GETPOST("zipcode",'alpha'),'chaine',0,'',$conf->entity);
+	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_STATE", GETPOST("state_id",'alpha'),'chaine',0,'',$conf->entity);
+	dolibarr_set_const($db, "MAIN_MONNAIE", GETPOST("currency",'alpha'),'chaine',0,'',$conf->entity);
+	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_TEL", GETPOST("tel",'alpha'),'chaine',0,'',$conf->entity);
+	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_FAX", GETPOST("fax",'alpha'),'chaine',0,'',$conf->entity);
+	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_MAIL", GETPOST("mail",'alpha'),'chaine',0,'',$conf->entity);
+	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_WEB", GETPOST("web",'alpha'),'chaine',0,'',$conf->entity);
+	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_NOTE", GETPOST("note",'none'),'chaine',0,'',$conf->entity);
+	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_GENCOD", GETPOST("barcode",'alpha'),'chaine',0,'',$conf->entity);
+
 	$varforimage='logo'; $dirforimage=$conf->mycompany->dir_output.'/logos/';
 	if ($_FILES[$varforimage]["tmp_name"])
 	{
@@ -100,8 +100,8 @@
 					if ($isimage > 0)
 					{
 					    // Create thumbs
-					    //$object->addThumbs($newfile);    // We can't use addThumbs here yet because we need name of generated thumbs to add them into constants. TODO Check if need such constants. We should be able to retreive value with get... 
-					    	
+					    //$object->addThumbs($newfile);    // We can't use addThumbs here yet because we need name of generated thumbs to add them into constants. TODO Check if need such constants. We should be able to retreive value with get...
+
 						// Create small thumb, Used on logon for example
 						$imgThumbSmall = vignette($dirforimage.$original_file, $maxwidthsmall, $maxheightsmall, '_small', $quality);
 						if (image_format_supported($imgThumbSmall) >= 0 && preg_match('/([^\\/:]+)$/i',$imgThumbSmall,$reg))
@@ -143,27 +143,27 @@
 			}
 		}
 	}
-	
-	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_MANAGERS",$_POST["MAIN_INFO_SOCIETE_MANAGERS"],'chaine',0,'',$conf->entity);
-	dolibarr_set_const($db, "MAIN_INFO_CAPITAL",$_POST["capital"],'chaine',0,'',$conf->entity);
-	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_FORME_JURIDIQUE",$_POST["forme_juridique_code"],'chaine',0,'',$conf->entity);
-	dolibarr_set_const($db, "MAIN_INFO_SIREN",$_POST["siren"],'chaine',0,'',$conf->entity);
-	dolibarr_set_const($db, "MAIN_INFO_SIRET",$_POST["siret"],'chaine',0,'',$conf->entity);
-	dolibarr_set_const($db, "MAIN_INFO_APE",$_POST["ape"],'chaine',0,'',$conf->entity);
-	dolibarr_set_const($db, "MAIN_INFO_RCS",$_POST["rcs"],'chaine',0,'',$conf->entity);
-	dolibarr_set_const($db, "MAIN_INFO_PROFID5",$_POST["MAIN_INFO_PROFID5"],'chaine',0,'',$conf->entity);
-	dolibarr_set_const($db, "MAIN_INFO_PROFID6",$_POST["MAIN_INFO_PROFID6"],'chaine',0,'',$conf->entity);
-
-	dolibarr_set_const($db, "MAIN_INFO_TVAINTRA",$_POST["tva"],'chaine',0,'',$conf->entity);
-	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_OBJECT",$_POST["object"],'chaine',0,'',$conf->entity);
-
-	dolibarr_set_const($db, "SOCIETE_FISCAL_MONTH_START",$_POST["fiscalmonthstart"],'chaine',0,'',$conf->entity);
-
-	dolibarr_set_const($db, "FACTURE_TVAOPTION",$_POST["optiontva"],'chaine',0,'',$conf->entity);
+
+	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_MANAGERS", GETPOST("MAIN_INFO_SOCIETE_MANAGERS",'alpha'),'chaine',0,'',$conf->entity);
+	dolibarr_set_const($db, "MAIN_INFO_CAPITAL", GETPOST("capital",'alpha'),'chaine',0,'',$conf->entity);
+	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_FORME_JURIDIQUE", GETPOST("forme_juridique_code",'alpha'),'chaine',0,'',$conf->entity);
+	dolibarr_set_const($db, "MAIN_INFO_SIREN", GETPOST("siren",'alpha'),'chaine',0,'',$conf->entity);
+	dolibarr_set_const($db, "MAIN_INFO_SIRET", GETPOST("siret",'alpha'),'chaine',0,'',$conf->entity);
+	dolibarr_set_const($db, "MAIN_INFO_APE", GETPOST("ape",'alpha'),'chaine',0,'',$conf->entity);
+	dolibarr_set_const($db, "MAIN_INFO_RCS", GETPOST("rcs",'alpha'),'chaine',0,'',$conf->entity);
+	dolibarr_set_const($db, "MAIN_INFO_PROFID5", GETPOST("MAIN_INFO_PROFID5",'alpha'),'chaine',0,'',$conf->entity);
+	dolibarr_set_const($db, "MAIN_INFO_PROFID6", GETPOST("MAIN_INFO_PROFID6",'alpha'),'chaine',0,'',$conf->entity);
+
+	dolibarr_set_const($db, "MAIN_INFO_TVAINTRA", GETPOST("tva",'alpha'),'chaine',0,'',$conf->entity);
+	dolibarr_set_const($db, "MAIN_INFO_SOCIETE_OBJECT", GETPOST("object",'nohtml'),'chaine',0,'',$conf->entity);
+
+	dolibarr_set_const($db, "SOCIETE_FISCAL_MONTH_START", GETPOST("fiscalmonthstart",'alpha'),'chaine',0,'',$conf->entity);
+
+	dolibarr_set_const($db, "FACTURE_TVAOPTION", GETPOST("optiontva",'alpha'),'chaine',0,'',$conf->entity);
 
 	// Local taxes
-	dolibarr_set_const($db, "FACTURE_LOCAL_TAX1_OPTION",$_POST["optionlocaltax1"],'chaine',0,'',$conf->entity);
-	dolibarr_set_const($db, "FACTURE_LOCAL_TAX2_OPTION",$_POST["optionlocaltax2"],'chaine',0,'',$conf->entity);
+	dolibarr_set_const($db, "FACTURE_LOCAL_TAX1_OPTION", GETPOST("optionlocaltax1",'alpha'),'chaine',0,'',$conf->entity);
+	dolibarr_set_const($db, "FACTURE_LOCAL_TAX2_OPTION", GETPOST("optionlocaltax2",'alpha'),'chaine',0,'',$conf->entity);
 
 	if($_POST["optionlocaltax1"]=="localtax1on")
 	{
@@ -173,9 +173,9 @@
 		}
 		else
 		{
-			dolibarr_set_const($db, "MAIN_INFO_VALUE_LOCALTAX1", GETPOST('lt1'),'chaine',0,'',$conf->entity);
-		}
-		dolibarr_set_const($db,"MAIN_INFO_LOCALTAX_CALC1", $_POST["clt1"],'chaine',0,'',$conf->entity);
+			dolibarr_set_const($db, "MAIN_INFO_VALUE_LOCALTAX1", GETPOST('lt1','alpha'),'chaine',0,'',$conf->entity);
+		}
+		dolibarr_set_const($db,"MAIN_INFO_LOCALTAX_CALC1",  GETPOST("clt1",'alpha'),'chaine',0,'',$conf->entity);
 	}
 	if($_POST["optionlocaltax2"]=="localtax2on")
 	{
@@ -185,9 +185,9 @@
 		}
 		else
 		{
-			dolibarr_set_const($db, "MAIN_INFO_VALUE_LOCALTAX2", GETPOST('lt2'),'chaine',0,'',$conf->entity);
-		}
-		dolibarr_set_const($db,"MAIN_INFO_LOCALTAX_CALC2", $_POST["clt2"],'chaine',0,'',$conf->entity);
+			dolibarr_set_const($db, "MAIN_INFO_VALUE_LOCALTAX2", GETPOST('lt2','alpha'),'chaine',0,'',$conf->entity);
+		}
... (diff truncated)
```
