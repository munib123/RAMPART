# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 294_2
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `294_2`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 89-129 of the vulnerable file.

<head>
<title>De Identification</title>
<link rel="stylesheet" href='<?php echo $css_header ?>' type='text/css'>
<script type="text/javascript" src="<?php echo $GLOBALS['webroot'] ?>/library/dialog.js?v=<?php echo $v_js_includes; ?>"></script>
<style type="text/css">
.style1 {
    text-align: center;
}
</style>
</head>
<body class="body_top">
<strong>De Identification</strong>
<form name="De Identification1" id="De Identification1" method="post"><br />
    <?php

    $query = "SELECT count(*) as count FROM metadata_de_identification";
    $res = sqlStatement($query);
    if ($row = sqlFetchArray($res)) {
        $no_of_items = addslashes($row['count']);
        if ($no_of_items == 0) {
            $cmd="cp ".$GLOBALS['webserver_root']."/sql/metadata_de_identification.txt ".$GLOBALS['temporary_files_dir']."/metadata_de_identification.txt";
            $output3=shell_exec($cmd);
            $query = "LOAD DATA INFILE '".$GLOBALS['temporary_files_dir']."/metadata_de_identification.txt' INTO TABLE metadata_de_identification FIELDS TERMINATED BY ','  LINES TERMINATED BY '\n'";
            $res = sqlStatement($query);
        }
    }

    //create transaction tables
    $query = "call create_transaction_tables()";
    $res = sqlStatement($query);

    //write input to data base
    $query = "delete from param_include_tables";
    $res = sqlStatement($query);

    $query = "insert into param_include_tables values ('$include_tables','$include_unstructured')";
    $res = sqlStatement($query);

    $query = "delete from param_filter_pid";
    $res = sqlStatement($query);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -106,9 +106,9 @@
     if ($row = sqlFetchArray($res)) {
         $no_of_items = addslashes($row['count']);
         if ($no_of_items == 0) {
-            $cmd="cp ".$GLOBALS['webserver_root']."/sql/metadata_de_identification.txt ".$GLOBALS['temporary_files_dir']."/metadata_de_identification.txt";
+            $cmd="cp " . escapeshellarg($GLOBALS['webserver_root']."/sql/metadata_de_identification.txt") . " " . escapeshellarg($GLOBALS['temporary_files_dir']."/metadata_de_identification.txt");
             $output3=shell_exec($cmd);
-            $query = "LOAD DATA INFILE '".$GLOBALS['temporary_files_dir']."/metadata_de_identification.txt' INTO TABLE metadata_de_identification FIELDS TERMINATED BY ','  LINES TERMINATED BY '\n'";
+            $query = "LOAD DATA INFILE '" . add_escape_custom($GLOBALS['temporary_files_dir']) ."/metadata_de_identification.txt' INTO TABLE metadata_de_identification FIELDS TERMINATED BY ','  LINES TERMINATED BY '\n'";
             $res = sqlStatement($query);
         }
     }
@@ -202,7 +202,7 @@
 
                         $timestamp = str_replace(" ", "_", $timestamp);
                         $de_identified_file = $GLOBALS['temporary_files_dir']."/de_identified_data".$timestamp.".xls";
-                        $query = "update de_identification_status set last_available_de_identified_data_file = '" . $de_identified_file . "'";
+                        $query = "update de_identification_status set last_available_de_identified_data_file = '" . add_escape_custom($de_identified_file) . "'";
                         $res = sqlStatement($query);
                         $query = "select * from de_identified_data into outfile '$de_identified_file' ";
                         $res = sqlStatement($query);
```
