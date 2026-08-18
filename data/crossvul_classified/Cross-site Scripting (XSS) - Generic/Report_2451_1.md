# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2451_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2451_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 14-54 of the vulnerable file.

);

?>

<div class="col-lg-12 list-surveys">

    <?php $this->renderPartial('super/fullpagebar_view', array(
        'fullpagebar' => array(
            'returnbutton'=>array(
                'url'=>'admin/survey/sa/listsurveys#surveygroups',
                'text'=>gT('Close'),
            ),
            'savebutton' => array(
                'form' => 'survey-settings-options-form'
            ),
            'saveandclosebutton' => array(
                'form' => 'survey-settings-options-form'
                )
                )
            )); ?>
    <h3><?php eT('Survey settings for group: '); echo '<strong><em>'.$model->title.'</strong></em>'; ?></h3>
    <div class="row">
        <div id="surveySettingsForThisGroup" style="display: flex; flex-wrap:nowrap;">
            <div id="global-sidebar-container">
                <global-sidemenu />
            </div>
            <div id="pjax-content" class="tab-content col-md-10">                
            <div class="row">
                <div class="alert alert-info controls col-sm-12" role="alert">
                    <?php eT('All changes of survey group settings will have immediate effect on all related surveys that use inherited values.'); ?>
                </div>
            </div>
            <?php echo CHtml::form(array("admin/surveysgroups/sa/surveysettings/id/".$oSurvey->gsid."/#surveySettingsGeneral"), 'post', array('id'=>'survey-settings-options-form')); ?>    
                <div class="tab-content col-md-10">
                <?php if($partial == '_generaloptions_panel') { ?> 
                        <div id="surveySettingsGeneral" class="row">
                            <?php $this->renderPartial('survey/subview/accordion/_generaloptions_panel', array(
                                    'oSurvey'=>$oSurvey,
                                    'oSurveyOptions' => $oSurvey->oOptionLabels,
                                    'bShowInherited' => $oSurvey->showInherited,
                                    'optionsOnOff' => $optionsOnOff,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,7 +31,7 @@
                 )
                 )
             )); ?>
-    <h3><?php eT('Survey settings for group: '); echo '<strong><em>'.$model->title.'</strong></em>'; ?></h3>
+    <h3><?php eT('Survey settings for group: '); echo '<strong><em>'.CHtml::encode($model->title).'</strong></em>'; ?></h3>
     <div class="row">
         <div id="surveySettingsForThisGroup" style="display: flex; flex-wrap:nowrap;">
             <div id="global-sidebar-container">
```
