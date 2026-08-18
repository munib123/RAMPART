# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 1444_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1444_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 902-942 of the vulnerable file.

                        $archiveFile = $sTempDir.DIRECTORY_SEPARATOR.randomChars(30);
                        file_put_contents($archiveFile, surveyGetXMLData($iSurveyID));
                        $this->_addToZip($zip, $archiveFile, $lssFileName);
                        unlink($archiveFile);
                    break;
                }
            } else {
                $aResults[$iSurveyID]['error'] = gT("We are sorry but you don't have permissions to do this.");
            }
        }
        return array('aResults'=>$aResults, 'sZip'=>$sZip, 'bArchiveIsEmpty'=>$bArchiveIsEmpty);
    }

    /**
     * Download an archive file
     * @param string $sZip name of zip file to download (will be downloaded as "surveys_archive.zip")
     */
    public function downloadZip($sZip)
    {
        $sTempDir     = Yii::app()->getConfig("tempdir");
        $aZIPFileName = $sTempDir.DIRECTORY_SEPARATOR.$sZip;

        if (is_file($aZIPFileName)) {
            $fn = "surveys_archive.zip";

            //Send the file for download!
            $this->_addHeaders($fn, "application/force-download", 0);

            @readfile($aZIPFileName);

            return;
        }
    }

    /**
     * Exports a archive (ZIP) of the current survey (structure, responses, timings, tokens)
     *
     * @param integer $iSurveyID  The ID of the survey to export
     * @param boolean $bSendToBrowser If TRUE (default) then the ZIP file is sent to the browser
     * @return string Full path of the ZIP filename if $bSendToBrowser is set to TRUE, otherwise no return value
     */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -919,6 +919,7 @@
     public function downloadZip($sZip)
     {
         $sTempDir     = Yii::app()->getConfig("tempdir");
+        $sZip         = get_absolute_path($sZip);
         $aZIPFileName = $sTempDir.DIRECTORY_SEPARATOR.$sZip;
 
         if (is_file($aZIPFileName)) {
```
