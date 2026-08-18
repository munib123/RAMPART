# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 137_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `137_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 22-62 of the vulnerable file.

	require (PAGE_DIR.'/'.get_page_filename($_GET['page']));

//If form is posted...
if (isset($_POST['save']) || isset($_POST['save_exit'])) {
	//Allow modules to add data to page
	$module_additional_data = null;
	run_hook('admin_save_page_afterpost', array(&$module_additional_data));

	if (!isset($_POST['hidden']))
		$_POST['hidden'] = 'yes';

	//Save the page, but only if a title has been entered and it's seo url is not empty.
	if (!empty($_POST['title']) && seo_url($_POST['title'])) {
		if (!empty($_POST['seo_name']) && $_POST['seo_name'] != seo_url($_POST['title'])) {
			$title = array('title' => $_POST['title'], 'seo_name' => trim(str_replace(array('\\', '/', ':', '*', '?', '"', '<', '>', '|'), '', $_POST['seo_name'])));
		}
		else
			$title = $_POST['title'];
		//If we are editing an existing page, pass current seo-name.
		if (isset($_GET['page'])) {
			$seoname = save_page($title, $_POST['content'], $_POST['hidden'], $_POST['sub_page'], $_POST['description'], $_POST['keywords'], $module_additional_data, $_GET['page']);
		} else {
		//If we are creating a new page, don't pass seo-name.
			$seoname = save_page($title, $_POST['content'], $_POST['hidden'], $_POST['sub_page'], $_POST['description'], $_POST['keywords'], $module_additional_data);
		}
		//If seoname is false, a file already exists with the same name
		if (empty($seoname)) {
			$error = show_error($lang['page']['name_exists'], 1, true);
		}
	} else {
	//If no title has been chosen or the seo url for the title is empty, set error.
		$error = show_error($lang['page']['no_title'], 1, true);
	}

	//Redirect to the new title only if it is a plain save.
	if (isset($_POST['save']) && !isset($error)) {
		redirect(SITE_URI.'/'.SITE_SCRIPT.'?action=editpage&page='.$seoname, 0);
		include_once ('data/inc/footer.php');
		exit;
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,10 +39,10 @@
 			$title = $_POST['title'];
 		//If we are editing an existing page, pass current seo-name.
 		if (isset($_GET['page'])) {
-			$seoname = save_page($title, $_POST['content'], $_POST['hidden'], $_POST['sub_page'], $_POST['description'], $_POST['keywords'], $module_additional_data, $_GET['page']);
+			$seoname = latinOnlyInput(save_page($title, $_POST['content'], $_POST['hidden'], $_POST['sub_page'], $_POST['description'], $_POST['keywords'], $module_additional_data, $_GET['page']));
 		} else {
 		//If we are creating a new page, don't pass seo-name.
-			$seoname = save_page($title, $_POST['content'], $_POST['hidden'], $_POST['sub_page'], $_POST['description'], $_POST['keywords'], $module_additional_data);
+			$seoname = latinOnlyInput(save_page($title, $_POST['content'], $_POST['hidden'], $_POST['sub_page'], $_POST['description'], $_POST['keywords'], $module_additional_data));
 		}
 		//If seoname is false, a file already exists with the same name
 		if (empty($seoname)) {
```
