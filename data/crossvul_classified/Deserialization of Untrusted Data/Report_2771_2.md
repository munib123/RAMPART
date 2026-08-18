# CrossVul Fix Pair: Deserialization of Untrusted Data in php
**Pair ID:** 2771_2
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2771_2`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```php
Lines 34-74 of the vulnerable file.

		
		$SystemHelperForm = new Form_SystemHelper();
		$SystemHelperFormResult = new Form_SystemHelperResult();
		
		$algo ="";
		$secret = "";
		$str = $request->getParam('StringToManipulate', false);
		$algo = $request->getParam('Algorithm', false);
		$key = $request->getParam('des_key',false);
		$secret = $request->getParam('secret',false);
		
		$res = "";
		
		
		if ( $algo == "wiki_encode" )
		{
			$res = str_replace ( array ( "|" , "/") , array ( "|01" , "|02" ) , base64_encode ( serialize ( $str ) ) ) ; 
		}
		elseif ( $algo == "wiki_decode" )
		{
			$res = @unserialize ( base64_decode (str_replace ( array ( "|02" , "|01" ) , array ( "/" , "|" ) , $str ) ) ) ;
		}
		elseif ( $algo == "wiki_decode_no_serialize" )
		{
			$res = base64_decode (str_replace ( array ( "|02" , "|01" ) , array ( "/" , "|" ) , $str ) ) ;
		}
		elseif ( $algo == "base64_encode" )
		{
			$res = base64_encode($str )		;
		}
		elseif ( $algo == "base64_decode" )
		{
			$res = base64_decode($str )		;
		}
		elseif ( $algo == "base64_3des_encode" )
		{
			$input = $str ;
			$td = mcrypt_module_open('tripledes', '', 'ecb', '');
	    	$iv = mcrypt_create_iv (mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
	    	$key = substr($key, 0, mcrypt_enc_get_key_size($td));
	    	
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -51,7 +51,7 @@
 		}
 		elseif ( $algo == "wiki_decode" )
 		{
-			$res = @unserialize ( base64_decode (str_replace ( array ( "|02" , "|01" ) , array ( "/" , "|" ) , $str ) ) ) ;
+			$res = null;
 		}
 		elseif ( $algo == "wiki_decode_no_serialize" )
 		{
```
