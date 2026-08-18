# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 47_1
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `47_1`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 43-83 of the vulnerable file.

     * Function responsible to import label resources from a '.zip' file.
     *
     * @access public
     * @return void
     */
    public function importlabelresources()
    {
        if (!Permission::model()->hasGlobalPermission('labelsets', 'edit')) {
            Yii::app()->session['flashmessage'] = gT('Access denied!');
            $this->getController()->redirect(App()->createUrl("/admin"));
        }
        $lid = returnGlobal('lid');
        if (!empty($lid)) {
            if (Yii::app()->getConfig('demoMode')) {
                            $this->getController()->error(gT("Demo mode only: Uploading files is disabled in this system."), $this->getController()->createUrl("admin/labels/sa/view/lid/{$lid}"));
            }

            // Create temporary directory
            // If dangerous content is unzipped
            // then no one will know the path
            $extractdir = $this->_tempdir(Yii::app()->getConfig('tempdir'));
            $zipfilename = $_FILES['the_file']['tmp_name'];
            $basedestdir = Yii::app()->getConfig('uploaddir')."/labels";
            $destdir = $basedestdir."/$lid/";

            Yii::app()->loadLibrary('admin.pclzip');
            $zip = new PclZip($zipfilename);

            if (!is_writeable($basedestdir)) {
                            $this->getController()->error(sprintf(gT("Incorrect permissions in your %s folder."), $basedestdir), $this->getController()->createUrl("admin/labels/sa/view/lid/{$lid}"));
            }

            if (!is_dir($destdir)) {
                            mkdir($destdir);
            }

            $aImportedFilesInfo = array();
            $aErrorFilesInfo = array();

            if (is_file($zipfilename)) {
                if ($zip->extract($extractdir) <= 0) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -60,7 +60,8 @@
             // Create temporary directory
             // If dangerous content is unzipped
             // then no one will know the path
-            $extractdir = $this->_tempdir(Yii::app()->getConfig('tempdir'));
+            Yii::import('application.helpers.common_helper', true);
+            $extractdir = createRandomTempDir();
             $zipfilename = $_FILES['the_file']['tmp_name'];
             $basedestdir = Yii::app()->getConfig('uploaddir')."/labels";
             $destdir = $basedestdir."/$lid/";
```
