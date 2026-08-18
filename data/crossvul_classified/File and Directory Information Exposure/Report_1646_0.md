# CrossVul Fix Pair: Files or Directories Accessible to External Parties in php
**Pair ID:** 1646_0
**Vulnerability Class:** File and Directory Information Exposure
**CWE:** CWE-552
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1646_0`)

## Vulnerability Information & PoC

## Description
Files or Directories Accessible to External Parties - Web servers, FTP servers, and similar servers may store a set of files underneath a root directory that is accessible to the server's users.

## Vulnerable Code
```php
Lines 55-96 of the vulnerable file.

     * @param array $httpHeaders 
     * @return string 
     */
    public function fetch($uri, $arguments = array(), $method = 'GET', $httpHeaders = array()) {
		
		$uri=str_replace('http://', 'https://', $uri); // all https, upload makes problems if not
		if (is_string($arguments) and strtoupper($method) == 'POST') {
		    preg_match("/\?file=(.*)$/i", $uri, $matches);
			if (isset($matches[1])) {
                $uri = str_replace($matches[0], "", $uri);
                $filename = $matches[1];
				$httpHeaders=array_merge($httpHeaders,$this->getOAuthHeader($uri, array("file" => $filename), $method));
            }
		} else {
			$httpHeaders=array_merge($httpHeaders,$this->getOAuthHeader($uri, $arguments, $method));
		}
		$ch = curl_init();	
		if (strtoupper($method) == 'POST') {
			curl_setopt($ch, CURLOPT_URL, $uri);
			curl_setopt($ch, CURLOPT_POST, true);
// 			if (is_array($arguments))
// 				$arguments=http_build_query($arguments);
			curl_setopt($ch, CURLOPT_POSTFIELDS, $arguments);
// 			$httpHeaders['Content-Length']=strlen($arguments);
		} else {
			curl_setopt($ch, CURLOPT_URL, $uri.'?'.http_build_query($arguments));
			curl_setopt($ch, CURLOPT_POST, false);
		}
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_TIMEOUT, 300);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
//         curl_setopt($ch, CURLOPT_CAINFO, "rootca");
		curl_setopt($ch, CURLOPT_FRESH_CONNECT, true);
		//Build header
		$headers = array();
		foreach ($httpHeaders as $name => $value) {
			$headers[] = "{$name}: $value";
		}
		curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
		if (!ini_get('safe_mode') && !ini_get('open_basedir'))
			curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -72,8 +72,14 @@
 		if (strtoupper($method) == 'POST') {
 			curl_setopt($ch, CURLOPT_URL, $uri);
 			curl_setopt($ch, CURLOPT_POST, true);
-// 			if (is_array($arguments))
-// 				$arguments=http_build_query($arguments);
+
+ 			//if (is_array($arguments))
+ 			//	$arguments=http_build_query($arguments);
+ 			foreach ($arguments as $key => $value) {
+ 				if($value[0] === '@') {
+					exit();
+				}
+			}
 			curl_setopt($ch, CURLOPT_POSTFIELDS, $arguments);
 // 			$httpHeaders['Content-Length']=strlen($arguments);
 		} else {
```
