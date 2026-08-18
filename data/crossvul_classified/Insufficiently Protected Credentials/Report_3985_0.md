# CrossVul Fix Pair: Insufficiently Protected Credentials in php
**Pair ID:** 3985_0
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-522
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3985_0`)

## Vulnerability Information & PoC

## Description
Insufficiently Protected Credentials - The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Vulnerable Code
```php
Lines 134-174 of the vulnerable file.

                   "destination" => array(tlInputParameter::STRING_N, 0, 255),
                   "loginform_token" => array(tlInputParameter::STRING_N, 0, 255),
                   "viewer" => array(tlInputParameter::STRING_N, 0, 3),
                   "oauth" => array(tlInputParameter::STRING_N,0,100),
                   "code" => array(tlInputParameter::STRING_N,0,4000),
                   "state" => array(tlInputParameter::STRING_N,0,100),
                  );
  $pParams = R_PARAMS($iParams);

  $args = new stdClass();
  $args->note = $pParams['note'];
  $args->login = $pParams['tl_login'];

  $args->pwd = $pParams['tl_password'];
  $args->ssodisable = getSSODisable();
  $args->reqURI = urlencode($pParams['req']);
  $args->preqURI = urlencode($pParams['reqURI']);
  $args->destination = urldecode($pParams['destination']);
  $args->loginform_token = urldecode($pParams['loginform_token']);

  $args->viewer = $pParams['viewer']; 

  $k2c = array('ajaxcheck' => 'do','ajaxlogin' => 'do');
  if (isset($k2c[$pParams['action']]))  {
    $args->action = $pParams['action'];
  } else if (!is_null($args->login)) {
    $args->action = 'doLogin';
  // This 'if' branch may be removed in later versions. Kept for compatibility    
  } else if (!is_null($pParams['oauth']) && $pParams['oauth']) {
    $args->action = 'oauth';
    $args->oauth_name = $pParams['oauth'];
    $args->oauth_code = $pParams['code'];
  } else if (!is_null($pParams['state']) && !is_null($pParams['code'])) {
    $args->action = 'oauth';
    $args->oauth_name = $pParams['state'];
    $args->oauth_code = $pParams['code'];
  } else {
    $args->action = 'loginform';
  }

  // whitelist oauth_name
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -151,7 +151,8 @@
   $args->destination = urldecode($pParams['destination']);
   $args->loginform_token = urldecode($pParams['loginform_token']);
 
-  $args->viewer = $pParams['viewer']; 
+  // $args->viewer = $pParams['viewer']; 
+  $args->viewer = '';
 
   $k2c = array('ajaxcheck' => 'do','ajaxlogin' => 'do');
   if (isset($k2c[$pParams['action']]))  {
```
