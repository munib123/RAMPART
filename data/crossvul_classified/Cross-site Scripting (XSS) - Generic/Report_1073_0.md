# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1073_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1073_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 89-130 of the vulnerable file.

     * those variables so that we don't end up in an error.
     *
     * This is also used while rendering wrapped template
     * {@link Survey_Common_Action::_renderWrappedTemplate()}
     *
     * @param array $params Parameters to parse and populate
     * @return array Populated parameters
     * @throws CHttpException
     */
    private function _addPseudoParams($params)
    {
        // Return if params isn't an array
        if (empty($params) || !is_array($params)) {
            return $params;
        }

        $pseudos = array(
            'id' => 'iId',
            'gid' => 'iGroupId',
            'qid' => 'iQuestionId',
            /* Unsure we set 'iSurveyId', 'iSurveyID','surveyid' to same final survey id */
            /* priority is surveyid,surveyId,sid : surveyId=1&sid=2 set sid surveyid to 1 */
            'sid' => array('iSurveyId', 'iSurveyID', 'surveyid'), // Old link use sid
            'surveyId' => array('iSurveyId', 'iSurveyID', 'surveyid'), // PluginHelper->sidebody : if disable surveyId usage : broke API
            'surveyid' => array('iSurveyId', 'iSurveyID', 'surveyid'),
            'srid' => 'iSurveyResponseId',
            'scid' => 'iSavedControlId',
            'uid' => 'iUserId',
            'ugid' => 'iUserGroupId',
            'fieldname' => 'sFieldName',
            'fieldtext' => 'sFieldText',
            'action' => 'sAction',
            'lang' => 'sLanguage',
            'browselang' => 'sBrowseLang',
            'tokenids' => 'aTokenIds',
            'tokenid' => 'iTokenId',
            'subaction' => 'sSubAction',
        );

        // Foreach pseudo, take the key, if it exists,
        // Populate the values (taken as an array) as keys in params
        // with that key's value in the params
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -106,8 +106,7 @@
             'id' => 'iId',
             'gid' => 'iGroupId',
             'qid' => 'iQuestionId',
-            /* Unsure we set 'iSurveyId', 'iSurveyID','surveyid' to same final survey id */
-            /* priority is surveyid,surveyId,sid : surveyId=1&sid=2 set sid surveyid to 1 */
+            /* priority is surveyid,surveyId,sid : surveyId=1&sid=2 set iSurveyId to 1 */
             'sid' => array('iSurveyId', 'iSurveyID', 'surveyid'), // Old link use sid
             'surveyId' => array('iSurveyId', 'iSurveyID', 'surveyid'), // PluginHelper->sidebody : if disable surveyId usage : broke API
             'surveyid' => array('iSurveyId', 'iSurveyID', 'surveyid'),
@@ -128,13 +127,16 @@
         // Foreach pseudo, take the key, if it exists,
         // Populate the values (taken as an array) as keys in params
         // with that key's value in the params
-        // (only if that place is empty)
+        // Chek is 2 params are equal for security issue.
         foreach ($pseudos as $key => $pseudo) {
             if (isset($params[$key])) {
                 $pseudo = (array) $pseudo;
                 foreach ($pseudo as $pseud) {
                     if (empty($params[$pseud])) {
                         $params[$pseud] = $params[$key];
+                    } elseif($params[$pseud] != $params[$key]){
+                        // Throw error about multiple params (and if they are different) #15204
+                        throw new CHttpException(403, sprintf(gT("Invalid parameter %s (%s already set)"),$pseud,$key));
                     }
                 }
             }
@@ -286,7 +288,6 @@
                         // Output
                     case 'output' :
                         //// TODO : http://goo.gl/ABl5t5
-
                         $content .= $viewUrl;
 
                         if (isset($aViewUrls['afteroutput'])) {
```
