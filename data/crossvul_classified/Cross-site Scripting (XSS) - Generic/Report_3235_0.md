# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3235_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3235_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-36 of the vulnerable file.

<?
defined('C5_EXECUTE') or die("Access Denied.");

$cp = FilePermissions::getGlobal();
if ((!$cp->canAddFile()) && (!$cp->canSearchFiles())) {
	die(t("Unable to access the file manager."));
}
Loader::model('file_list');

if (isset($_REQUEST['searchInstance'])) {
	$searchInstance = Loader::helper('text')->entities($_REQUEST['searchInstance']);
} else {
	$searchInstance = $page . time();
}
$ocID = Loader::helper('text')->entities($_REQUEST['ocID']);

$cnt = Loader::controller('/dashboard/files/search');
$fileList = $cnt->getRequestedSearchResults();
$files = $fileList->getPage();
$pagination = $fileList->getPagination();
$searchRequest = $cnt->get('searchRequest');
$columns = $cnt->get('columns');

$alType = 'false';
if (isset($_REQUEST['disable_choose']) && $_REQUEST['disable_choose'] == 1) { 
	$alType = 'BROWSE';
}

ob_start();
Loader::element('files/search_results', array('ocID' => $ocID, 'searchInstance' => $searchInstance, 'searchRequest' => $searchRequest, 'columns' => $columns, 'searchType' => 'DIALOG', 'files' => $files, 'fileList' => $fileList)); $searchForm = ob_get_contents();
ob_end_clean();

$v = View::getInstance();
$v->outputHeaderItems();


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,6 +13,7 @@
 	$searchInstance = $page . time();
 }
 $ocID = Loader::helper('text')->entities($_REQUEST['ocID']);
+$disable_choose = Loader::helper('text')->entities($_REQUEST['disable_choose']);
 
 $cnt = Loader::controller('/dashboard/files/search');
 $fileList = $cnt->getRequestedSearchResults();
@@ -22,7 +23,7 @@
 $columns = $cnt->get('columns');
 
 $alType = 'false';
-if (isset($_REQUEST['disable_choose']) && $_REQUEST['disable_choose'] == 1) { 
+if ($disable_choose == 1) { 
 	$alType = 'BROWSE';
 }
 
@@ -40,7 +41,7 @@
 	<div id="ccm-<?=$searchInstance?>-overlay-wrapper">
 <? } ?>
 <div id="ccm-<?=$searchInstance?>-search-overlay" class="ccm-ui">
-	<input type="hidden" name="dialogAction" value="<?=REL_DIR_FILES_TOOLS_REQUIRED?>/files/search_dialog?ocID=<?=$_REQUEST['ocID']?>&searchInstance=<?=$searchInstance?>&disable_choose=<?=$_REQUEST['disable_choose']?>" />
+	<input type="hidden" name="dialogAction" value="<?=REL_DIR_FILES_TOOLS_REQUIRED?>/files/search_dialog?ocID=<?=$ocID?>&amp;searchInstance=<?=$searchInstance?>&amp;disable_choose=<?=$disable_choose?>" />
 
 <div class="ccm-pane-options" id="ccm-<?=$searchInstance?>-pane-options">
 
```
