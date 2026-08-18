# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4241_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4241_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 38-78 of the vulnerable file.


        $this->userId = Yii::app()->user->getId();

        if (!Yii::app()->getConfig("surveyid")) {Yii::app()->setConfig("surveyid", returnGlobal('sid')); }         //SurveyID
        if (!Yii::app()->getConfig("surveyID")) {Yii::app()->setConfig("surveyID", returnGlobal('sid')); }         //SurveyID
        if (!Yii::app()->getConfig("ugid")) {Yii::app()->setConfig("ugid", returnGlobal('ugid')); }                //Usergroup-ID
        if (!Yii::app()->getConfig("gid")) {Yii::app()->setConfig("gid", returnGlobal('gid')); }                   //GroupID
        if (!Yii::app()->getConfig("qid")) {Yii::app()->setConfig("qid", returnGlobal('qid')); }                   //QuestionID
        if (!Yii::app()->getConfig("lid")) {Yii::app()->setConfig("lid", returnGlobal('lid')); }                   //LabelID
        if (!Yii::app()->getConfig("code")) {Yii::app()->setConfig("code", returnGlobal('code')); }                // ??
        if (!Yii::app()->getConfig("action")) {Yii::app()->setConfig("action", returnGlobal('action')); }          //Desired action
        if (!Yii::app()->getConfig("subaction")) {Yii::app()->setConfig("subaction", returnGlobal('subaction')); } //Desired subaction
        if (!Yii::app()->getConfig("editedaction")) {Yii::app()->setConfig("editedaction", returnGlobal('editedaction')); } // for html editor integration

        // This line is needed for template editor to work
        AdminTheme::getInstance();

        Yii::setPathOfAlias('lsadminmodules', Yii::app()->getConfig('lsadminmodulesrootdir'));
    }

    /**
     * This part comes from _renderWrappedTemplate (not the best way to refactoring, but a temporary solution)
     *
     * todo REFACTORING find all actions that set $aData['surveyid'] and change the layout directly in the action
     *
     * @param string $view
     * @return bool
     */
    protected function beforeRender($view)
    {
        //this lines come from _renderWarppedTemplate
        //todo: this should be moved to the new questioneditor controller when it is being refactored
        /*
        if (isset($this->aData['surveyid'])) {
            $this->aData['oSurvey'] = Survey::model()->findByPk($this->aData['surveyid']);

            // Needed to evaluate EM expressions in question summary
            // See bug #11845
            LimeExpressionManager::SetSurveyId($this->aData['surveyid']);
            LimeExpressionManager::StartProcessingPage(false, true);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -56,6 +56,72 @@
     }
 
     /**
+     * Validate params validity and read access on survey
+     * @Throw CHttpException
+     * @return void
+     */
+    protected function checkParams()
+    {
+        /* qid and iQuestionId */
+        $qid = $iQuestionId = null;
+        $qid = App()->getRequest()->getParam('qid');
+        $iQuestionId = App()->getRequest()->getParam('iQuestionId');
+        if ($qid && $iQuestionId && $qid != $iQuestionId) {
+            throw new CHttpException(400);
+        }
+        $qid = $qid ? $qid : $iQuestionId;
+        if($qid) {
+            $oQuestion = Question::model()->findByPk($qid);
+            if(!$oQuestion) {
+                throw new CHttpException(404);
+            }
+        }
+        /* gid */
+        $gid = null;
+        $gid = App()->getRequest()->getQuery('gid');
+        if ($gid && $oQuestion && $gid != $oQuestion->gid) {
+            throw new CHttpException(400);
+        }
+        if ($gid) {
+            $oGroup = QuestionGroup::model()->findByPk($gid);
+            if(!$oGroup) {
+                throw new CHttpException(404);
+            }
+        }
+        /* sid, iSurveyId, $surveyid , $surveyID … why use different param name each time */
+        $currentSid = $sid = $iSurveyId = $surveyid = $surveyID = null;
+        $sid = App()->getRequest()->getParam('sid');
+        if ($sid)  {
+            $currentSid = $sid;
+        }
+        $iSurveyId = App()->getRequest()->getParam('iSurveyId');
+        if ($currentSid && $iSurveyId && $currentSid != $iSurveyId) {
+            throw new CHttpException(400);
+        }
+        $currentSid = $currentSid ? $currentSid : $iSurveyId;
+        $surveyid = App()->getRequest()->getParam('surveyid');
+        if ($currentSid && $surveyid && $currentSid != $surveyid) {
+            throw new CHttpException(400);
+        }
+        $currentSid = $currentSid ? $currentSid : $surveyid;
+        $surveyID = App()->getRequest()->getParam('surveyID');
+        if ($currentSid && $surveyID && $currentSid != $surveyID) {
+            throw new CHttpException(400);
+        }
+        $currentSid = $currentSid ? $currentSid : $surveyID;
+        /* Concordence of sid */
+        if ($currentSid && $oQuestion && $currentSid != $oQuestion->sid) {
+            throw new CHttpException(400);
+        }
+        if ($currentSid && $oGroup && $currentSid != $oGroup->sid) {
+            throw new CHttpException(400);
+        }
+        /* Minimal access */
+        if ($currentSid && !Permission::model()->hasSurveyPermission($currentSid, 'survey', 'read')) {
+            throw new CHttpException(403);
+        }
+    }
+    /**
      * This part comes from _renderWrappedTemplate (not the best way to refactoring, but a temporary solution)
      *
      * todo REFACTORING find all actions that set $aData['surveyid'] and change the layout directly in the action
@@ -136,6 +202,7 @@
                 }
             }
         }
+        $this->checkParams();
 
         parent::run($action);
     }
```
