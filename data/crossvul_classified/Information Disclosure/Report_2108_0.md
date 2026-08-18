# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 2108_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2108_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 210-250 of the vulnerable file.

  
  if ( isset($_GET["base_path"]) ) {
    $base_path = rawurldecode($_GET["base_path"]);
    $file = $base_path . $file; # Set the input file
  }  
  
  if ( isset($_GET["options"]) ) {
    $options = $_GET["options"];
  }
  
  $file_parts = explode_url($file);
  
  /* Check to see if the input file is local and, if so, that the base path falls within that specified by DOMDPF_CHROOT */
  if(($file_parts['protocol'] == '' || $file_parts['protocol'] === 'file://')) {
    $file = realpath($file);
    if ( strpos($file, DOMPDF_CHROOT) !== 0 ) {
      throw new DOMPDF_Exception("Permission denied on $file. The file could not be found under the directory specified by DOMPDF_CHROOT.");
    }
  }
  
  $outfile = "dompdf_out.pdf"; # Don't allow them to set the output file
  $save_file = false; # Don't save the file
  
  break;
}

$dompdf = new DOMPDF();

if ( $file === "-" ) {
  $str = "";
  while ( !feof(STDIN) )
    $str .= fread(STDIN, 4096);

  $dompdf->load_html($str);

} else
  $dompdf->load_html_file($file);

if ( isset($base_path) ) {
  $dompdf->set_base_path($base_path);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -227,6 +227,10 @@
     }
   }
   
+  if($file_parts['protocol'] === 'php://') {
+    throw new DOMPDF_Exception("Permission denied on $file. This script does not allow PHP streams.");
+  }
+  
   $outfile = "dompdf_out.pdf"; # Don't allow them to set the output file
   $save_file = false; # Don't save the file
   
```
