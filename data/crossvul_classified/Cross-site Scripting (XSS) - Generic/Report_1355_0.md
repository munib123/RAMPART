# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1355_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1355_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 75-115 of the vulnerable file.

 *
 */
function initEnv() {
  $iParams = array("reqURI" => array(tlInputParameter::STRING_N,0,4000));
  $pParams = G_PARAMS($iParams);
  
  $args = new stdClass();
  $args->ssodisable = getSSODisable();

  // CWE-79: 
  // Improper Neutralization of Input 
  // During Web Page Generation ('Cross-site Scripting')
  // 
  // https://cxsecurity.com/issue/WLB-2019110139
  $args->reqURI = '';
  if ($pParams["reqURI"] != '') {
    $args->reqURI = $pParams["reqURI"];

    // some sanity checks
    // strpos ( string $haystack , mixed $needle
    if (strpos($args->reqURI,'javascript') !== false) {
      $args->reqURI = null; 
    }
  }
  if (null == $args->reqURI) {
    $args->reqURI = 'lib/general/mainPage.php';
  }
  $args->reqURI = $_SESSION['basehref'] . $args->reqURI;



  $args->tproject_id = isset($_REQUEST['tproject_id']) ? intval($_REQUEST['tproject_id']) : 0;
  $args->tplan_id = isset($_REQUEST['tplan_id']) ? intval($_REQUEST['tplan_id']) : 0;

  $gui = new stdClass();
  $gui->title = lang_get('main_page_title');
  $gui->mainframe = $args->reqURI;
  $gui->navbar_height = config_get('navbar_height');

  $sso = ($args->ssodisable ? '&ssodisable' : '');
  $gui->titleframe = "lib/general/navBar.php?" . 
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -92,7 +92,7 @@
 
     // some sanity checks
     // strpos ( string $haystack , mixed $needle
-    if (strpos($args->reqURI,'javascript') !== false) {
+    if (stripos($args->reqURI,'javascript') !== false) {
       $args->reqURI = null; 
     }
   }
```
