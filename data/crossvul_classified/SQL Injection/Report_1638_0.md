# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 1638_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1638_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 19-59 of the vulnerable file.

 * questiongroup
 *
 * @package LimeSurvey
 * @author
 * @copyright 2011
  * @access public
 */
class questiongroups extends Survey_Common_Action
{

    /**
     * questiongroup::import()
     * Function responsible to import a question group.
     *
     * @access public
     * @return void
     */
    function import()
    {
        $action = $_POST['action'];
        $surveyid = $_POST['sid'];

        if ($action == 'importgroup')
        {
            $importgroup = "\n";
            $importgroup .= "\n";

            $sFullFilepath = Yii::app()->getConfig('tempdir') . DIRECTORY_SEPARATOR . randomChars(20);
            $aPathInfo = pathinfo($_FILES['the_file']['name']);
            $sExtension = $aPathInfo['extension'];

            if (!@move_uploaded_file($_FILES['the_file']['tmp_name'], $sFullFilepath))
            {
                $fatalerror = sprintf(gT("An error occurred uploading your file. This may be caused by incorrect permissions in your %s folder."), $this->config->item('tempdir'));
            }

            // validate that we have a SID
            if (!returnGlobal('sid'))
                $fatalerror .= gT("No SID (Survey) has been provided. Cannot import question.");

            if (isset($fatalerror))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -36,7 +36,7 @@
     function import()
     {
         $action = $_POST['action'];
-        $surveyid = $_POST['sid'];
+        $iSurveyID = (int)$_POST['sid'];
 
         if ($action == 'importgroup')
         {
@@ -66,11 +66,11 @@
 
             // IF WE GOT THIS FAR, THEN THE FILE HAS BEEN UPLOADED SUCCESFULLY
             if (strtolower($sExtension) == 'lsg')
-                $aImportResults = XMLImportGroup($sFullFilepath, $surveyid);
+                $aImportResults = XMLImportGroup($sFullFilepath, $iSurveyID);
             else
                 $this->getController()->error('Unknown file extension');
             LimeExpressionManager::SetDirtyFlag(); // so refreshes syntax highlighting
-            fixLanguageConsistency($surveyid);
+            fixLanguageConsistency($iSurveyID);
 
             if (isset($aImportResults['fatalerror']))
             {
@@ -81,7 +81,7 @@
             unlink($sFullFilepath);
 
             $aData['display'] = $importgroup;
-            $aData['surveyid'] = $surveyid;
+            $aData['surveyid'] = $iSurveyID;
             $aData['aImportResults'] = $aImportResults;
             $aData['sExtension'] = $sExtension;
             //$aData['display']['menu_bars']['surveysummary'] = 'importgroup';
```
