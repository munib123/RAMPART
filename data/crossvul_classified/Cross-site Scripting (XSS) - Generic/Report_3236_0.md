# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3236_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3236_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-29 of the vulnerable file.

<?
defined('C5_EXECUTE') or die("Access Denied.");

if (!Loader::helper('validation/numbers')->integer($_REQUEST['fID'])) {
	die(t('Access Denied'));
}

$selectedField = Loader::helper('text')->entities($_REQUEST['ccm_file_selected_field']);

$u = new User();
$form = Loader::helper('form');
$fp = FilePermissions::getGlobal();
if (!$fp->canAccessFileManager()) {
	die(t("Unable to access the file manager."));
}



$f = File::getByID($_REQUEST['fID']);
$fp = new Permissions($f);
if (!$fp->canViewFileInFileManager()) {
	die(t("Access Denied."));
}

$fv = $f->getApprovedVersion();

$canViewInline = $fv->canView() ? 1 : 0;
$canEdit = $fv->canEdit() ? 1 : 0;
?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,6 +6,7 @@
 }
 
 $selectedField = Loader::helper('text')->entities($_REQUEST['ccm_file_selected_field']);
+$fID = Loader::helper('text')->entities($_REQUEST['fID']);
 
 $u = new User();
 $form = Loader::helper('form');
@@ -16,7 +17,7 @@
 
 
 
-$f = File::getByID($_REQUEST['fID']);
+$f = File::getByID($fID);
 $fp = new Permissions($f);
 if (!$fp->canViewFileInFileManager()) {
 	die(t("Access Denied."));
@@ -28,7 +29,7 @@
 $canEdit = $fv->canEdit() ? 1 : 0;
 ?>
 
-<div class="ccm-file-selected" fID="<?=$_REQUEST['fID']?>" ccm-file-manager-field="<?=$selectedField?>" ccm-file-manager-can-duplicate="<?=$fp->canCopyFile()?>" ccm-file-manager-can-admin="<?=($fp->canEditFilePermissions())?>" ccm-file-manager-can-delete="<?=$fp->canDeleteFile()?>" ccm-file-manager-can-view="<?=$canViewInline?>" ccm-file-manager-can-replace="<?=$fp->canEditFileContents()?>" ccm-file-manager-can-edit="<?=$canEdit?>"  >
+<div class="ccm-file-selected" fID="<?=$fID?>" ccm-file-manager-field="<?=$selectedField?>" ccm-file-manager-can-duplicate="<?=$fp->canCopyFile()?>" ccm-file-manager-can-admin="<?=($fp->canEditFilePermissions())?>" ccm-file-manager-can-delete="<?=$fp->canDeleteFile()?>" ccm-file-manager-can-view="<?=$canViewInline?>" ccm-file-manager-can-replace="<?=$fp->canEditFileContents()?>" ccm-file-manager-can-edit="<?=$canEdit?>"  >
 <div class="ccm-file-selected-thumbnail"><?=$fv->getThumbnail(1)?></div>
 <div class="ccm-file-selected-data"><div><?=$fv->getTitle()?></div><div></div></div>
 <div class="ccm-spacer">&nbsp;</div>
```
