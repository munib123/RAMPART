# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 378_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `378_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 6-46 of the vulnerable file.


$this->require_admin ();

$this->run ('admin/util/i18n');

$page->title = __ ('Page title');
$page->preview = true;
$page->layout = false;

if ($_SERVER['REQUEST_METHOD'] == 'GET') {
	if (! empty ($_GET['layout'])) {
		if (strpos ($_GET['layout'], '..') === false) {
			if (file_exists ('layouts/' . $_GET['layout'] . '.html')) {
				$page->layout = file_get_contents ('layouts/' . $_GET['layout'] . '.html');
			} elseif (file_exists ('layouts/' . $_GET['layout'] . '/' . $_GET['layout'] . '.html')) {
				$page->layout = file_get_contents ('layouts/' . $_GET['layout'] . '/' . $_GET['layout'] . '.html');
			}
		}
	}
	if ($_GET['css'] && preg_match ('/^(layouts|css)\/[a-z0-9\/ _-]+\.css$/i', $_GET['css'])) {
		$page->layout = str_replace ('</head>', '<style>' . file_get_contents ($_GET['css']) . '</style></head>', $page->layout);
	}
} else {
	if (! empty ($_POST['layout'])) {
		if (strpos ($_POST['layout'], '..') === false) {
			if (file_exists ('layouts/' . $_POST['layout'] . '.html')) {
				$page->layout = file_get_contents ('layouts/' . $_POST['layout'] . '.html');
			} elseif (file_exists ('layouts/' . $_POST['layout'] . '/' . $_POST['layout'] . '.html')) {
				$page->layout = file_get_contents ('layouts/' . $_POST['layout'] . '/' . $_POST['layout'] . '.html');
			}
		}
	}
	if ($_POST['css']) {
		$page->layout = str_replace ('</head>', '<style>' . $_POST['css'] . '</style></head>', $page->layout);
	}	
}

if ($page->layout === false) {
	$page->layout = conf ('General', 'default_layout');
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,7 +23,7 @@
 		}
 	}
 	if ($_GET['css'] && preg_match ('/^(layouts|css)\/[a-z0-9\/ _-]+\.css$/i', $_GET['css'])) {
-		$page->layout = str_replace ('</head>', '<style>' . file_get_contents ($_GET['css']) . '</style></head>', $page->layout);
+		$page->layout = str_replace ('</head>', '<style>' . strip_tags (file_get_contents ($_GET['css'])) . '</style></head>', $page->layout);
 	}
 } else {
 	if (! empty ($_POST['layout'])) {
@@ -36,7 +36,7 @@
 		}
 	}
 	if ($_POST['css']) {
-		$page->layout = str_replace ('</head>', '<style>' . $_POST['css'] . '</style></head>', $page->layout);
+		$page->layout = str_replace ('</head>', '<style>' . strip_tags ($_POST['css']) . '</style></head>', $page->layout);
 	}	
 }
 
```
