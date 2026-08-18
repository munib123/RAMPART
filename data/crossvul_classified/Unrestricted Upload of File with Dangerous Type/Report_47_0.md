# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 47_0
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `47_0`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 331-371 of the vulnerable file.

    * to a temporary location, updating length (size) values in the $fields array as
    * the tmp file is generated (uses @fwrite's return value rather than strlen).
    * Final output renders $fields to a DATA LIST, and then stitches in the tmp file data.
    *
    * Optimization opportunities remain in the VALUE LABELS section, which runs a query / column
    */
    public function exportspss()
    {
        global $length_vallabel;
        $iSurveyID = sanitize_int(Yii::app()->request->getParam('sid'));
        $oSurvey = Survey::model()->findByPk($iSurveyID);
        //for scale 1=nominal, 2=ordinal, 3=scale

        //        $typeMap = $this->_getTypeMap();

        $filterstate = incompleteAnsFilterState();
        if (!Yii::app()->session['spssversion']) {
// Default to 2 (16 and up)
            Yii::app()->session['spssversion'] = 2;
        }
        $spssver = Yii::app()->request->getParam('spssver', Yii::app()->session['spssversion']); 
        Yii::app()->session['spssversion'] = $spssver;

        $length_varlabel = '231'; // Set the max text length of Variable Labels
        $length_vallabel = '120'; // Set the max text length of Value Labels

        switch ($spssver) {
            case 1:    //<16
                $iLength = '255'; // Set the max text length of the Value
                break;
            case 2:    //>=16
            default:
                $iLength = '16384'; // Set the max text length of the Value
        }

        $headerComment = '*$Rev: 121017 $'." $filterstate $spssver.\n";

        if (Yii::app()->request->getPost('dldata')) {
            $subaction = "dldata";
        }
        if (Yii::app()->request->getPost('dlstructure')) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -348,7 +348,7 @@
 // Default to 2 (16 and up)
             Yii::app()->session['spssversion'] = 2;
         }
-        $spssver = Yii::app()->request->getParam('spssver', Yii::app()->session['spssversion']); 
+        $spssver = Yii::app()->request->getParam('spssver', Yii::app()->session['spssversion']);
         Yii::app()->session['spssversion'] = $spssver;
 
         $length_varlabel = '231'; // Set the max text length of Variable Labels
@@ -1150,7 +1150,7 @@
 
 
             $lang = Yii::app()->request->getPost('save_language');
-            $tempdir = Yii::app()->getConfig("tempdir");
+
 
             // Setting the selected language for printout
             App()->setLanguage($lang);
@@ -1169,7 +1169,9 @@
             //NEED TO GET QID from $quexmlpdf
             $qid = intval($quexmlpdf->getQuestionnaireId());
 
-            $zipdir = $this->_tempdir($tempdir);
+            Yii::import('application.helpers.common_helper', true);
+            $zipdir = createRandomTempDir();
+
 
             $f1 = "$zipdir/quexf_banding_{$qid}_{$lang}.xml";
             $f2 = "$zipdir/quexmlpdf_{$qid}_{$lang}.pdf";
@@ -1185,7 +1187,7 @@
 
 
             Yii::app()->loadLibrary('admin.pclzip');
-            $zipfile = "$tempdir/quexmlpdf_{$qid}_{$lang}.zip";
+            $zipfile = Yii::app()->getConfig("tempdir").DIRECTORY_SEPARATOR."quexmlpdf_{$qid}_{$lang}.zip";
             $z = new PclZip($zipfile);
             $z->create($zipdir, PCLZIP_OPT_REMOVE_PATH, $zipdir);
 
@@ -1222,10 +1224,12 @@
         $fullAssetsDir = Template::getTemplatePath($oSurvey->template);
         $aLanguages = $oSurvey->getAllLanguages();
 
+        Yii::import('application.helpers.common_helper', true);
+        $zipdir = createRandomTempDir();
+
+        $fn = "printable_survey_".preg_replace('([^\w\s\d\-_~,;\[\]\(\).])','',$oSurvey->currentLanguageSettings->surveyls_title)."_{$oSurvey->primaryKey}.zip";
+
         $tempdir = Yii::app()->getConfig("tempdir");
-        $zipdir = $this->_tempdir($tempdir);
-
-        $fn = "printable_survey_".preg_replace('([^\w\s\d\-_~,;\[\]\(\).])','',$oSurvey->currentLanguageSettings->surveyls_title)."_{$oSurvey->primaryKey}.zip";
         $zipfile = "$tempdir/".$fn;
 
         Yii::app()->loadLibrary('admin.pclzip');
```
