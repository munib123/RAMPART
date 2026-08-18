# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 294_1
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `294_1`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 543-583 of the vulnerable file.

        ++$stmt_count;
    }

    fclose($fhprint);
    sleep(1);
    // Download or print the file, as selected
    if ($_POST['form_download']) {
        upload_file_to_client($STMT_TEMP_FILE);
    } elseif ($_POST['form_pdf']) {
        upload_file_to_client_pdf($STMT_TEMP_FILE, $aPatientFirstName, $aPatientID, $usePatientNamePdf);
    } elseif ($_POST['form_email']) {
                upload_file_to_client_email($stmt['pid'], $STMT_TEMP_FILE);
    } elseif ($_POST['form_portalnotify']) {
        if ($alertmsg == "") {
            $alertmsg = xl('Sending Invoice to Patient Portal Completed');
        }
    } else { // Must be print!
        if ($DEBUG) {
            $alertmsg = xl("Printing skipped; see test output in") .' '. $STMT_TEMP_FILE;
        } else {
            exec("$STMT_PRINT_CMD $STMT_TEMP_FILE");
            if ($_POST['form_without']) {
                $alertmsg = xl('Now printing') .' '. $stmt_count .' '. xl('statements; invoices will not be updated.');
            } else {
                $alertmsg = xl('Now printing') .' '. $stmt_count .' '. xl('statements and updating invoices.');
            }
        } // end not debug
    } // end not form_download
} // end statements requested
    ?>
  <html>
  <head>
        <?php Header::setupHeader(['datetime-picker']);?>
    <title><?php xl('EOB Posting - Search', 'e'); ?></title>
    <script language="JavaScript">
    var mypcc = '1';

    function checkAll(checked) {
        var f = document.forms[0];
        for (var i = 0; i < f.elements.length; ++i) {
        var ename = f.elements[i].name;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -560,7 +560,7 @@
         if ($DEBUG) {
             $alertmsg = xl("Printing skipped; see test output in") .' '. $STMT_TEMP_FILE;
         } else {
-            exec("$STMT_PRINT_CMD $STMT_TEMP_FILE");
+            exec(escapeshellcmd($STMT_PRINT_CMD) . " " . escapeshellarg($STMT_TEMP_FILE));
             if ($_POST['form_without']) {
                 $alertmsg = xl('Now printing') .' '. $stmt_count .' '. xl('statements; invoices will not be updated.');
             } else {
@@ -705,13 +705,13 @@
                         &nbsp;<span><?php echo xlt('Select Method');?></span>&nbsp;<i id='select-method-tooltip' class="fa fa-info-circle oe-superscript" aria-hidden="true"></i>
                         <div id="radio-div" class="pull-right oe-legend-radio">
                                 <label class="radio-inline">
-                                  <input type="radio" id="invoice_search" name="radio-search" onclick="" value="inv-search"><?php echo xlt('Invoice Search'); ?> 
+                                  <input type="radio" id="invoice_search" name="radio-search" onclick="" value="inv-search"><?php echo xlt('Invoice Search'); ?>
                                 </label>
                                 <label class="radio-inline">
                                   <input type="radio" id="era_upload" name="radio-search" onclick=""  value="era-upld"><?php echo xlt('ERA Upload'); ?>
                                 </label>
                         </div>
-                        
+
                         <input type="hidden" id="hid1" value="<?php echo xlt('Invoice Search');?>">
                         <input type="hidden" id="hid2" value="<?php echo xlt('ERA Upload');?>">
                         <input type="hidden" id="hid3" value="<?php echo xlt('Select Method');?>">
@@ -755,11 +755,11 @@
                     </div>
                     <div class="col-xs-12 .oe-custom-line oe-show-hide" id = 'era-upld'>
                         <div class="form-group col-xs9 oe-file-div">
-                            <div class="input-group"> 
+                            <div class="input-group">
                                 <label class="input-group-btn">
                                     <span class="btn btn-default">
                                         Browse&hellip;<input type="file" id="uploadedfile" name="form_erafile" style="display: none;" >
-                                        <input name="MAX_FILE_SIZE" type="hidden" value="5000000"> 
+                                        <input name="MAX_FILE_SIZE" type="hidden" value="5000000">
                                     </span>
                                 </label>
                                 <input type="text" class="form-control" placeholder="<?php echo xlt('Click Browse and select one Electronic Remittance Advice (ERA) file...'); ?>" readonly>
@@ -771,9 +771,9 @@
                 <div class="form-group clearfix">
                     <div class="col-sm-12 position-override oe-show-hide" id="search-btn">
                         <div class="btn-group" role="group">
-                            <button type='submit' class="btn btn-default btn-search oe-show-hide" name='form_search' 
+                            <button type='submit' class="btn btn-default btn-search oe-show-hide" name='form_search'
                             id="btn-inv-search" value='<?php echo xla("Search"); ?>'><?php echo xlt("Search"); ?></button>
-                            <button type='submit' class="btn btn-default btn-save oe-show-hide" name='form_search' 
+                            <button type='submit' class="btn btn-default btn-save oe-show-hide" name='form_search'
                             id="btn-era-upld" value='<?php echo xla("Upload"); ?>'><?php echo xlt("Upload"); ?></button>
                         </div>
                     </div>
@@ -802,7 +802,7 @@
                                     exec("unzip -p $tmp_name.zip > $tmp_name");
                                     unlink("$tmp_name.zip");
                                 }
-                                
+
                                 echo "<!-- Notes from ERA upload processing:\n";
                                 $alertmsg .= parse_era($tmp_name, 'era_callback');
                                 echo "-->\n";
@@ -1055,14 +1055,14 @@
                                 <button type="button" class="btn btn-default btn-undo" name="Submit2"
                                 onclick='checkAll(false)'><?php echo xlt('Clear All');?></button>
                                 <?php if ($GLOBALS['statement_appearance'] != '1') { ?>
-                                    <button type="submit" class="btn btn-default btn-print" name='form_print' 
+                                    <button type="submit" class="btn btn-default btn-print" name='form_print'
                                     value="<?php echo xla('Print Selected Statements'); ?>">
                                     <?php echo xlt('Print Selected Statements');?></button>
-                                    <button type="submit" class="btn btn-default btn-download" name='form_download' 
+                                    <button type="submit" class="btn btn-default btn-download" name='form_download'
                                     value="<?php echo xla('Download Selected Statements'); ?>">
                                     <?php echo xlt('Download Selected Statements');?></button>
                                 <?php } ?>
-                                    <button type="submit" class="btn btn-default btn-download" name='form_pdf' 
+                                    <button type="submit" class="btn btn-default btn-download" name='form_pdf'
                                     value="<?php echo xla('PDF Download Selected Statements'); ?>">
                                     <?php echo xlt('PDF Download Selected Statements');?></button>
                                     <button type="submit" class="btn btn-default btn-mail" name='form_download'
@@ -1093,7 +1093,7 @@
         //help_modal.php lives in interface, set path accordingly
         require_once "../help_modal.php";
     }
-    ?> 
+    ?>
     <script language="JavaScript">
     function processERA() {
      var f = document.forms[0];
@@ -1117,10 +1117,10 @@
             $(':file').on('fileselect', function(event, numFiles, label) {
                 var input = $(this).parents('.input-group').find(':text'),
                 log = numFiles > 1 ? numFiles + ' files selected' : label;
-                
+
                 if( input.length ) {
                 input.val(log);
-                } 
+                }
                 else {
                 if( log ) alert(log);
                 }
@@ -1196,6 +1196,6 @@
     <?php
     }
     ?>
-    
+
 </body>
 </html>
```
