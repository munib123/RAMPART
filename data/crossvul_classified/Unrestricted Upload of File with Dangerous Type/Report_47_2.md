# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 47_2
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `47_2`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 255-295 of the vulnerable file.

     * Function responsible to import survey resources from a '.zip' file.
     *
     * @access public
     * @return void
     */
    public function importsurveyresources()
    {
        $iSurveyID = Yii::app()->request->getPost('surveyid');

        if (!empty($iSurveyID)) {


            if (Yii::app()->getConfig('demoMode')) {
                Yii::app()->user->setFlash('error', gT("Demo mode only: Uploading files is disabled in this system."));
                $this->getController()->redirect(array('admin/survey/sa/editlocalsettings/surveyid/'.$iSurveyID));
            }

            // Create temporary directory
            // If dangerous content is unzipped
            // then no one will know the path
            $extractdir  = $this->_tempdir(Yii::app()->getConfig('tempdir'));
            $zipfilename = $_FILES['the_file']['tmp_name'];
            $basedestdir = Yii::app()->getConfig('uploaddir')."/surveys";
            $destdir     = $basedestdir."/$iSurveyID/";

            Yii::app()->loadLibrary('admin.pclzip');
            $zip = new PclZip($zipfilename);

            if (!is_writeable($basedestdir)) {
                Yii::app()->user->setFlash('error', sprintf(gT("Incorrect permissions in your %s folder."), $basedestdir));
                $this->getController()->redirect(array('admin/survey/sa/editlocalsettings/surveyid/'.$iSurveyID));
            }


            if (!is_dir($destdir)) {
                mkdir($destdir);
            }

            $aImportedFilesInfo = array();
            $aErrorFilesInfo = array();

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -272,7 +272,8 @@
             // Create temporary directory
             // If dangerous content is unzipped
             // then no one will know the path
-            $extractdir  = $this->_tempdir(Yii::app()->getConfig('tempdir'));
+            Yii::import('application.helpers.common_helper', true);
+            $extractdir  = createRandomTempDir();
             $zipfilename = $_FILES['the_file']['tmp_name'];
             $basedestdir = Yii::app()->getConfig('uploaddir')."/surveys";
             $destdir     = $basedestdir."/$iSurveyID/";
```
