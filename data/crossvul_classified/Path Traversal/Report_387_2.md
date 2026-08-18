# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 387_2
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `387_2`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 111-151 of the vulnerable file.


        $tmp .= $lrow['title'];
        if ($lrow['comments']) {
            $tmp .= ' (' . $lrow['comments'] . ')';
        }
    }

    return $tmp;
}

// Top level function for scanning and replacement of a file's contents.
function doSubs($s)
{
    global $ptrow, $hisrow, $enrow, $nextLocation, $keyLocation, $keyLength;
    global $groupLevel, $groupCount, $itemSeparator, $pid, $encounter;
    global $tcnt, $grcnt, $ckcnt;
    global $html_flag;
    $nextLocation = 0;
    $groupLevel = 0;
    $groupCount = 0;
    
    while (($keyLocation = strpos($s, '{', $nextLocation)) !== false) {
        $nextLocation = $keyLocation + 1;
        
        if (keySearch($s, '{PatientSignature}')) {
            $fn = $GLOBALS['web_root'] . '/portal/sign/assets/signhere.png';
            $sigfld = '<span>';
            $sigfld .= '<img style="cursor:pointer;color:red" class="signature" type="patient-signature" id="patientSignature" onclick="getSignature(this)"' . 'alt="' . xla("Click in signature on file") . '" src="' . $fn . '">';
            $sigfld .= '</span>';
            $s = keyReplace($s, $sigfld);
        } else if (keySearch($s, '{AdminSignature}')) {
            $fn = $GLOBALS['web_root'] . '/portal/sign/assets/signhere.png';
            $sigfld = '<span>';
            $sigfld .= '<img style="cursor:pointer;color:red" class="signature" type="admin-signature" id="adminSignature" onclick="getSignature(this)"' . 'alt="' . xla("Click in signature on file") . '" src="' . $fn . '">';
            $sigfld .= '</span>';
            $s = keyReplace($s, $sigfld);
        } else if (keySearch($s, '{ParseAsHTML}')) {
            $html_flag = true;
            $s = keyReplace($s, "");
        } else if (keySearch($s, '{TextInput}')) {
            $sigfld = '<span>';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -128,10 +128,10 @@
     $nextLocation = 0;
     $groupLevel = 0;
     $groupCount = 0;
-    
+
     while (($keyLocation = strpos($s, '{', $nextLocation)) !== false) {
         $nextLocation = $keyLocation + 1;
-        
+
         if (keySearch($s, '{PatientSignature}')) {
             $fn = $GLOBALS['web_root'] . '/portal/sign/assets/signhere.png';
             $sigfld = '<span>';
@@ -231,7 +231,7 @@
             $patientid = $ptrow['pid'];
             $DOS = substr($enrow['date'], 0, 10);
             // Prefer appointment comment if one is present.
-            $evlist = fetchEvents($DOS, $DOS, " AND pc_pid = '$patientid' ");
+            $evlist = fetchEvents($DOS, $DOS, " AND pc_pid = ? ", null, false, 0, array($patientid));
             foreach ($evlist as $tmp) {
                 if ($tmp['pc_pid'] == $pid && ! empty($tmp['pc_hometext'])) {
                     $cc = $tmp['pc_hometext'];
@@ -345,7 +345,7 @@
             $s = keyReplace($s, dataFixup($data, $title));
         }
     } // End if { character found.
-    
+
     return $s;
 }
 // Get patient demographic info.
@@ -368,9 +368,12 @@
 }
 
 $templatedir = $GLOBALS['OE_SITE_DIR'] . '/documents/onsite_portal_documents/templates';
+
+check_file_dir_name($form_filename);
 $templatepath = "$templatedir/$form_filename";
 // test if this is folder with template, if not, must be for a specific patient
 if (! file_exists($templatepath)) {
+    check_file_dir_name($pid);
     $templatepath = "$templatedir/" . $pid . "/$form_filename";
 }
 
```
