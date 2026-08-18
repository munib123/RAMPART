# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 399_0
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `399_0`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 316-375 of the vulnerable file.

        case 92: // pixlr (image editor) overlay remover
        case 'pixlr_exit':
			ob_clean();
            file::thumbnails_remove(intval($_GET['id']));

			echo '
			<html>
			<head></head>
			<body>
			<script language="javascript" type="text/javascript">
				//window.parent.eval("$(\'#thumbnail-cache\').attr(\'src\', $(\'#thumbnail-cache\').attr(\'src\') + \'&refresh=\' + new Date().getTime());");
				window.parent.eval(\'$("#image-preview").attr("src", $("#image-preview").attr("src") + "&refresh=" + new Date().getTime());\');
				window.parent.eval("pixlr.overlay.hide();");
			</script>
			</body>
			</html>	
			';
			
			core_terminate();
			break;
		/*	
		case 91: // picnik editing
			ob_clean();
			
			// $strPicnikUrl is the URL that we use to launch Picnik.
			$strPicnikUrl = "http://www.picnik.com/service";	
			// $aPicnikParams collects together all the params we'll give Picnik.  Start with an API key
			$aPicnikParams['_apikey'] = $website->picnik_api_key;
			// tell Picnik where to send the exported image
			$aPicnikParams['_export'] = NAVIGATE_URL.'/navigate_upload.php?wid='.$website->id.'&engine=picnik&id='.$_REQUEST['id'].'&engine=picnik&session_id='.session_id();
			// give the export button a title
			$aPicnikParams['_export_title'] = t(34, 'Save');
			// turn on the close button, and tell it to come back here
			//$aPicnikParams['_close_target'] = $strRoot;
			// send in the previous "king" image in case the user feels like decorating it
			$aPicnikParams['_import'] = NAVIGATE_DOWNLOAD.'?wid='.$website->id.'&id='.$_REQUEST['id'].'&disposition=attachment&sid='.session_id();	
			// tell Picnik to redirect the user to the following URL after the HTTP POST instead of just redirecting to _export
			$aPicnikParams['_redirect'] = NAVIGATE_DOWNLOAD.'?wid='.$website->id.'&id='.$_REQUEST['id'].'&disposition=inline&ts='.core_time(); //'javascript: return false;';
		
			// tell Picnik our name.  It'll use it in a few places as appropriate
			$aPicnikParams['_host_name'] = 'Navigate';
			// turn off the "Save &amp; Share" tab so users don't get confused
			$aPicnikParams['_exclude'] = "out";
		
			echo '<html><head></head><body>';
		
			echo '<form id="picnik_form" method="POST" action="'.$strPicnikUrl.'" style=" visibility: hidden; ">';
			
			// put all the API parameters into the form as hidden inputs
			foreach( $aPicnikParams as $key => $value ) {
				echo "<input type='hidden' name='$key' value='$value'/>\n";
			}
			
			//echo "<input type='text' name='address' value='Your Majesty'/>\n";
			echo "<input type='submit' value='Picnik'/>\n";
			echo "</form>";
			echo '<script language="javascript" type="text/javascript">
					document.forms[0].submit();
				  </script>';
			echo '</body></html>';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -333,50 +333,6 @@
 			
 			core_terminate();
 			break;
-		/*	
-		case 91: // picnik editing
-			ob_clean();
-			
-			// $strPicnikUrl is the URL that we use to launch Picnik.
-			$strPicnikUrl = "http://www.picnik.com/service";	
-			// $aPicnikParams collects together all the params we'll give Picnik.  Start with an API key
-			$aPicnikParams['_apikey'] = $website->picnik_api_key;
-			// tell Picnik where to send the exported image
-			$aPicnikParams['_export'] = NAVIGATE_URL.'/navigate_upload.php?wid='.$website->id.'&engine=picnik&id='.$_REQUEST['id'].'&engine=picnik&session_id='.session_id();
-			// give the export button a title
-			$aPicnikParams['_export_title'] = t(34, 'Save');
-			// turn on the close button, and tell it to come back here
-			//$aPicnikParams['_close_target'] = $strRoot;
-			// send in the previous "king" image in case the user feels like decorating it
-			$aPicnikParams['_import'] = NAVIGATE_DOWNLOAD.'?wid='.$website->id.'&id='.$_REQUEST['id'].'&disposition=attachment&sid='.session_id();	
-			// tell Picnik to redirect the user to the following URL after the HTTP POST instead of just redirecting to _export
-			$aPicnikParams['_redirect'] = NAVIGATE_DOWNLOAD.'?wid='.$website->id.'&id='.$_REQUEST['id'].'&disposition=inline&ts='.core_time(); //'javascript: return false;';
-		
-			// tell Picnik our name.  It'll use it in a few places as appropriate
-			$aPicnikParams['_host_name'] = 'Navigate';
-			// turn off the "Save &amp; Share" tab so users don't get confused
-			$aPicnikParams['_exclude'] = "out";
-		
-			echo '<html><head></head><body>';
-		
-			echo '<form id="picnik_form" method="POST" action="'.$strPicnikUrl.'" style=" visibility: hidden; ">';
-			
-			// put all the API parameters into the form as hidden inputs
-			foreach( $aPicnikParams as $key => $value ) {
-				echo "<input type='hidden' name='$key' value='$value'/>\n";
-			}
-			
-			//echo "<input type='text' name='address' value='Your Majesty'/>\n";
-			echo "<input type='submit' value='Picnik'/>\n";
-			echo "</form>";
-			echo '<script language="javascript" type="text/javascript">
-					document.forms[0].submit();
-				  </script>';
-			echo '</body></html>';
-
-			core_terminate();
-			break;
-		*/
 		
 		case 0: // list / search result
 		default:						
```
