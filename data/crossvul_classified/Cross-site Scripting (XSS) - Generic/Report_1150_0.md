# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1150_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1150_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 22-62 of the vulnerable file.


	Contributor(s):
	Mark J Crane <markjcrane@fusionpbx.com>
*/

function paging($num_rows, $param, $rows_per_page, $mini = false, $result_count = 0) {

	//validate the data
	if (!is_numeric($num_rows)) { $num_rows = 0; }
	if (!is_numeric($rows_per_page)) { $rows_per_page = 100; }
	if (!is_numeric($result_count)) { $result_count = 0; }

	// if $_get['page'] defined, use it as page number
	if(isset($_GET['page']) && is_numeric($_GET['page'])) {
		$page_number = $_GET['page'];
	}
	else {
		$page_number = 0;
	}

	//get the offset
	$offset = ($page_number - 1) * $rows_per_page;

	//how many pages we have when using paging
	if ($num_rows > 0) {
		$max_page = ceil($num_rows/$rows_per_page);
	}

	//add multi-lingual support
	$language = new text;
	$text = $language->get();

	// print the link to access each page
	$self = $_SERVER['PHP_SELF'];
	$nav = '';
	for($page = 1; $page <= $max_page; $page++){
		if ($page == $page_number) {
			$nav .= " $page ";   // no need to create a link to current page
		}
		else {
			$nav .= " <a href=\"$self?page=$page\">$page</a> \n";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,6 +39,40 @@
 		$page_number = 0;
 	}
 
+	//sanitize the parameters
+	$sanitized_parameters = '';
+	if (isset($param) && strlen($param) > 0) {
+		$param_array = explode("&", $param);
+		if (is_array($param_array)) {
+			foreach($param_array as $row) {
+				$param_sub_array = explode("=", $row);
+				$key = preg_replace('#[^a-zA-Z0-9_\-]#', '', $param_sub_array['0']);
+				$value = urldecode($param_sub_array['1']);
+				if ($key == 'order_by' && strlen($value) > 0) {
+					//validate order by
+					$sanitized_parameters .= "&order_by=". preg_replace('#[^a-zA-Z0-9_\-]#', '', $value);
+				}
+				elseif ($key == 'order' && strlen($value) > 0) {
+					//validate order
+					switch ($value) {
+						case 'asc':
+							$sanitized_parameters .= "&order=asc";
+							break;
+						case 'desc':
+							$sanitized_parameters .= "&order=desc";
+							break;
+					}
+				}
+				elseif (strlen($value) > 0 && is_numeric($value)) {
+					$sanitized_parameters .= "&".$key."=".$value;
+				}
+				else {
+					$sanitized_parameters .= "&".$key."=".urlencode($value);
+				}
+			}
+		}
+	}
+
 	//get the offset
 	$offset = ($page_number - 1) * $rows_per_page;
 
@@ -51,8 +85,8 @@
 	$language = new text;
 	$text = $language->get();
 
-	// print the link to access each page
-	$self = $_SERVER['PHP_SELF'];
+	//print the link to access each page
+	$self =  escape($_SERVER['PHP_SELF']);
 	$nav = '';
 	for($page = 1; $page <= $max_page; $page++){
 		if ($page == $page_number) {
@@ -64,21 +98,21 @@
 	}
 
 	if ($page_number > 0) {
-        $page = $page_number - 1;
-		$prev = "<input class='btn' type='button' value='".$text['button-back']."' alt='".($page+1)."' title='".($page+1)."' onClick=\"window.location = '".$self."?page=$page".$param."';\">\n"; //&#9664;
-		$first = "<input class='btn' type='button' value='".$text['button-next']."' onClick=\"window.location = '".$self."?page=1".$param."';\">\n"; //&#9650;
+		$page = $page_number - 1;
+		$prev = "<input class='btn' type='button' value='".$text['button-back']."' alt='".($page+1)."' title='".($page+1)."' onClick=\"window.location = '".$self."?page=".$page.$sanitized_parameters."';\">\n"; //&#9664;
+		$first = "<input class='btn' type='button' value='".$text['button-next']."' onClick=\"window.location = '".$self."?page=1".$sanitized_parameters."';\">\n"; //&#9650;
 	}
 	else {
 		$prev = "<input class='btn' type='button' disabled value='".$text['button-back']."' style='opacity: 0.4; -moz-opacity: 0.4; cursor: default;'>\n"; //&#9664;
 	}
 
 	if (($page_number + 1) < $max_page) {
-        $page = $page_number + 1;
-		$next = "<input class='btn' type='button' value='".$text['button-next']."' alt='".($page+1)."' title='".($page+1)."' onClick=\"window.location = '".$self."?page=$page".$param."';\">\n"; //&#9654;
-		$last = "<input class='btn' type='button' value='".$text['button-back']."' onClick=\"window.location = '".$self."?page=$max_page".$param."';\">\n"; //&#9660;
+		$page = $page_number + 1;
+		$next = "<input class='btn' type='button' value='".$text['button-next']."' alt='".($page+1)."' title='".($page+1)."' onClick=\"window.location = '".$self."?page=".$page.$sanitized_parameters."';\">\n"; //&#9654;
+		$last = "<input class='btn' type='button' value='".$text['button-back']."' onClick=\"window.location = '".$self."?page=".$max_page.$sanitized_parameters."';\">\n"; //&#9660;
 	}
 	else {
-		$last = "<input class='btn' type='button' value='".$text['button-next']."' onClick=\"window.location = '".$self."?page=$max_page".$param."';\">\n"; //&#9660;
+		$last = "<input class='btn' type='button' value='".$text['button-next']."' onClick=\"window.location = '".$self."?page=".$max_page.$sanitized_parameters."';\">\n"; //&#9660;
 		$next = "<input class='btn' type='button' disabled value='".$text['button-next']."' style='opacity: 0.4; -moz-opacity: 0.4; cursor: default;'>\n"; //&#9654;
 	}
 
@@ -123,7 +157,7 @@
 							"// action to peform when enter is hit\n".
 							"if (page_num < 1) { page_num = 1; }\n".
 							"if (page_num > ".$max_page.") { page_num = ".$max_page."; }\n".
-							"document.location.href = '".$self."?page='+(--page_num)+'".$param."';\n".
+							"document.location.href = '".$self."?page='+(--page_num)+'".$sanitized_parameters."';\n".
 						"}\n".
 					"}\n".
 				"</script>\n";
```
