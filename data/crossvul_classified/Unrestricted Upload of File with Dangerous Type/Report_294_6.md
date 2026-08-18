# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 294_6
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `294_6`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 297-337 of the vulnerable file.

        //
        $tmp1 = array();
        $tmp2 = 0;
        $tmpfn1 = tempnam("/tmp", "fax1");
        $tmpfn2 = tempnam("/tmp", "fax2");
        $tmph = fopen($tmpfn1, "w");
        $cpstring = '';
        $fh = fopen($GLOBALS['OE_SITE_DIR'] . "/faxcover.txt", 'r');
        while (!feof($fh)) {
            $cpstring .= fread($fh, 8192);
        }

        fclose($fh);
        $cpstring = str_replace('{CURRENT_DATE}', date('F j, Y'), $cpstring);
        $cpstring = str_replace('{SENDER_NAME}', $form_from, $cpstring);
        $cpstring = str_replace('{RECIPIENT_NAME}', $form_to, $cpstring);
        $cpstring = str_replace('{RECIPIENT_FAX}', $form_fax, $cpstring);
        $cpstring = str_replace('{MESSAGE}', $form_message, $cpstring);
        fwrite($tmph, $cpstring);
        fclose($tmph);
        $tmp0 = exec("cd $webserver_root/custom; " . $GLOBALS['hylafax_enscript'] .
        " -o $tmpfn2 $tmpfn1", $tmp1, $tmp2);
        if ($tmp2) {
              $info_msg .= "enscript returned $tmp2: $tmp0 ";
        }

        unlink($tmpfn1);

        // Send the fax as the cover page followed by the selected pages.
        $info_msg .= mergeTiffs();
        $tmp0 = exec(
            "sendfax -A -n $form_finemode -d " .
            escapeshellarg($form_fax) . " $tmpfn2 '$faxcache/temp.tif'",
            $tmp1,
            $tmp2
        );
        if ($tmp2) {
              $info_msg .= "sendfax returned $tmp2: $tmp0 ";
        }

        unlink($tmpfn2);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -314,7 +314,7 @@
         $cpstring = str_replace('{MESSAGE}', $form_message, $cpstring);
         fwrite($tmph, $cpstring);
         fclose($tmph);
-        $tmp0 = exec("cd $webserver_root/custom; " . $GLOBALS['hylafax_enscript'] .
+        $tmp0 = exec("cd $webserver_root/custom; " . escapeshellcmd($GLOBALS['hylafax_enscript']) .
         " -o $tmpfn2 $tmpfn1", $tmp1, $tmp2);
         if ($tmp2) {
               $info_msg .= "enscript returned $tmp2: $tmp0 ";
```
