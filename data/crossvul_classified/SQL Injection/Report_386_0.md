# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 386_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `386_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 48-88 of the vulnerable file.

    $filename   = "Fax_".$encounter."_".$to_data['lname'].".pdf";

    $query = "SELECT * FROM documents where encounter_id=? and foreign_id=? and url like ?";
    $doc = sqlQuery($query, array($encounter,$pid,'%'.$filename.'%' ));


    $sql = "SELECT * from form_taskman where FROM_ID=? and TO_ID=? and PATIENT_ID=? and ENC_ID=?";
    $task = sqlQuery($sql, array($from_id,$to_id,$patient_id,$enc));

    if (!$doc['ID'] && $task['ID'] && ($task['REQ_DATE'] < (time() - 60))) {
        // The task was requested more than a minute ago (prevents multi-clicks from "re-generating" the PDF),
        // but the document was deleted (to redo it)...
        // Delete the task, recreate the task, and send the newly made PDF.
        $sql = "DELETE from form_taskman where FROM_ID=? and TO_ID=? and PATIENT_ID=? and ENC_ID=?";
        $task = sqlQuery($sql, array($from_id,$to_id,$patient_id,$enc));
    }

    if ($task['ID'] && $task['COMPLETED'] =='2') {
        $send['comments'] = xlt('This fax has already been sent.')." ".
                            xlt('If you made changes and want to re-send it, delete the original (in Communications) or wait 60 seconds, and try again.')." ".
                            xlt('Filename').": ".$filename;
        echo json_encode($send);
        exit;
    } else if ($task['ID'] && $task['COMPLETED'] =='1') {
        if ($task['DOC_TYPE'] == 'Fax') {
            $send['DOC_link'] = "<a href='".$webroot."/openemr/controller.php?document&view&patient_id=".$task['PATIENT_ID']."&doc_id=".$task['DOC_ID']."'
								target='_blank' title='".xla('View the Summary Report sent to Fax Server.')."'>
								<i class='fa fa-file-pdf-o fa-fw'></i></a>
								<i class='fa fa-repeat fa-fw'
									onclick=\"top.restoreSession(); create_task('".attr($pat_data['ref_providerID'])."','Fax-resend','ref'); return false;\">
									</i>
							";
                            //add a resend option.
            $send['comments'] = xlt('This fax has already been sent.');
            echo json_encode($send);
            exit;
        } else if ($task['DOC_TYPE'] == "Fax-resend") {
            //we need to resend this fax????
            //You can only resend from here once.
            $send['comments'] = xlt('To resend, delete the file from Communications, reload this page and try again.');
            echo json_encode($send);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -65,12 +65,12 @@
     if ($task['ID'] && $task['COMPLETED'] =='2') {
         $send['comments'] = xlt('This fax has already been sent.')." ".
                             xlt('If you made changes and want to re-send it, delete the original (in Communications) or wait 60 seconds, and try again.')." ".
-                            xlt('Filename').": ".$filename;
+                            xlt('Filename').": ". text($filename);
         echo json_encode($send);
         exit;
     } else if ($task['ID'] && $task['COMPLETED'] =='1') {
         if ($task['DOC_TYPE'] == 'Fax') {
-            $send['DOC_link'] = "<a href='".$webroot."/openemr/controller.php?document&view&patient_id=".$task['PATIENT_ID']."&doc_id=".$task['DOC_ID']."'
+            $send['DOC_link'] = "<a href='".$webroot."/openemr/controller.php?document&view&patient_id=".attr($task['PATIENT_ID'])."&doc_id=".attr($task['DOC_ID'])."'
 								target='_blank' title='".xla('View the Summary Report sent to Fax Server.')."'>
 								<i class='fa fa-file-pdf-o fa-fw'></i></a>
 								<i class='fa fa-repeat fa-fw'
@@ -94,8 +94,8 @@
     } else if (!$task['ID']) {
         $sql = "INSERT into form_taskman
 				(REQ_DATE, FROM_ID,  TO_ID,  PATIENT_ID,  DOC_TYPE,  DOC_ID,  ENC_ID) VALUES
-				(NOW(), '$from_id', '$to_id','$patient_id','$doc_type','$doc_id','$enc')";
-        sqlQuery($sql);
+				(NOW(), ?, ?, ?, ?, ?, ?)";
+        sqlQuery($sql, array($from_id, $to_id, $patient_id, $doc_type, $doc_id, $enc));
     } else {
         $send['comments'] = xlt('Currently working on making this document')."...\n";
     }
@@ -121,7 +121,7 @@
 
     if ($task['DOC_TYPE'] == "Fax") {
         //now return any objects you need to Eye Form
-        $send['DOC_link'] = "<a href='".$webroot."/openemr/controller.php?document&view&patient_id=".$task['PATIENT_ID']."&doc_id=".$task['DOC_ID']."'
+        $send['DOC_link'] = "<a href='".$webroot."/openemr/controller.php?document&view&patient_id=".attr($task['PATIENT_ID'])."&doc_id=".attr($task['DOC_ID'])."'
 								target='_blank' title=".xlt('Report was faxed. Click to view.').">
 								<i class='fa fa-file-pdf-o fa-fw'></i>
 							</a>";
@@ -339,7 +339,7 @@
         $sql = "DELETE from documents where documents.url like ?";
         sqlQuery($sql, array("%".$filename));
     }
-    
+
     $config_mpdf = array(
         'tempDir' => $GLOBALS['MPDF_WRITE_DIR'],
         'mode' => $GLOBALS['pdf_language'],
@@ -465,7 +465,7 @@
                         <td class='col1'>
                             <?php echo xlt('Comments'); ?>:
                         </td>
-                        <td class='col2'><?php echo xlt('Report of visit'); ?>: <?php echo text($pt_name); ?> on <?php echo $visit_date; ?>
+                        <td class='col2'><?php echo xlt('Report of visit'); ?>: <?php echo text($pt_name); ?> on <?php echo text($visit_date); ?>
                         </td>
                     </tr>
             </table>
```
