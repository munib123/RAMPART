# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3706_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3706_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 15-74 of the vulnerable file.

 */

class Reporters_Controller extends Admin_Controller
{
	function __construct()
	{
		parent::__construct();
		$this->template->this_page = 'messages';
		
		// If user doesn't have access, redirect to dashboard
		if ( ! $this->auth->has_permission("messages_reporters"))
		{
			url::redirect(url::site().'admin/dashboard');
		}
	}
	
	public function index($service_id = 1)
	{
		$this->template->content = new View('admin/reporters/main');
		$this->template->content->title = Kohana::lang('ui_admin.reporters');
		
		$filter = "1=1";
		$search_type = "";
		$keyword = "";
		// Get Search Type (If Any)
		if ($service_id)
		{
			$search_type = $service_id;
			$filter .= " AND (service_id='".$service_id."')";
		}
		else
		{
			$search_type = "0";
		}
		
		// Get Search Keywords (If Any)
		if (isset($_GET['k']) AND !empty($_GET['k']))
		{
			$keyword = $_GET['k'];
			$filter .= " AND (service_account LIKE'%".$_GET['k']."%')";
		}
		
		// setup and initialize form field names
		$form = array
		(
			'reporter_id' => '',
			'level_id' => '',
			'service_name' => '',
			'service_account' => '',
			'location_id' => '',
			'location_name' => '',
			'latitude' => '',
			'longitude' => ''
		);
		//  copy the form as errors, so the errors will be stored with keys corresponding to the form field names
		$errors = $form;
		$form_error = FALSE;
		$form_saved = FALSE;
		$form_action = "";

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,27 +32,6 @@
 	{
 		$this->template->content = new View('admin/reporters/main');
 		$this->template->content->title = Kohana::lang('ui_admin.reporters');
-		
-		$filter = "1=1";
-		$search_type = "";
-		$keyword = "";
-		// Get Search Type (If Any)
-		if ($service_id)
-		{
-			$search_type = $service_id;
-			$filter .= " AND (service_id='".$service_id."')";
-		}
-		else
-		{
-			$search_type = "0";
-		}
-		
-		// Get Search Keywords (If Any)
-		if (isset($_GET['k']) AND !empty($_GET['k']))
-		{
-			$keyword = $_GET['k'];
-			$filter .= " AND (service_account LIKE'%".$_GET['k']."%')";
-		}
 		
 		// setup and initialize form field names
 		$form = array
@@ -181,6 +160,24 @@
 			}
 		}
 
+		// Start building query
+		$filter = '1=1 ';
+		
+		// Default search type to service id
+		$search_type = ( isset($_GET['s']) ) ? intval($_GET['s']) : intval($service_id);
+		if ($search_type > 0)
+		{
+			$filter .= 'AND service_id = '.intval($search_type).' ';
+		}
+		
+		// Get Search Keywords (If Any)
+		$keyword = '';
+		if (isset($_GET['k']) AND !empty($_GET['k']))
+		{
+			$keyword = $_GET['k'];
+			$filter .= 'AND service_account LIKE \'%'.Database::instance()->escape_str($_GET['k']).'%\' ';
+		}
+
 		// Pagination
 		$pagination = new Pagination(array(
 		                    'query_string' => 'page',
```
