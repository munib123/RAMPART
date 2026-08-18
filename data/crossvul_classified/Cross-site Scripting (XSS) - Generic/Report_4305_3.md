# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4305_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4305_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 8-48 of the vulnerable file.

$tooltip = null;
$icon = null;
if ($oQuota->action == Quota::ACTION_TERMINATE){
    $tooltip = gT("Terminate survey");
    $icon = 'fa-exclamation-circle';
} elseif ($oQuota->action == Quota::ACTION_CONFIRM_TERMINATE){
    $tooltip = gT("Allow user to modify his last answers before terminate survey.");
    $icon = 'fa-exclamation-triangle';
}
?>

<?php /*echo "<pre>".print_r($oQuota->mainLanguagesetting->attributes,true)."</pre>";*/ ?>
<div class="panel panel-<?php echo ($oQuota->active==1 ? 'primary' : 'default') ?>">
    <div class="panel-heading">
        <div class="pull-right small">
            <span><span class="fa <?php echo $icon?>"></span> <?php echo $tooltip;?></span>
            <?php if($oQuota->autoload_url == 1):?>
                <span><span class="fa fa-external-link"></span> <?php echo gT('Autoload URL:').' '.htmlentities($oQuota->mainLanguagesetting->quotals_url);?></span>
            <?php endif;?>
        </div>
        <?php echo viewHelper::flatEllipsizeText($oQuota->name) ;?>
    </div>
    <table class="table table-quota-items table-striped table-condensed" >
        <thead>
            <tr>
                <th><?php eT('Question');?></th>
                <th><?php eT('Answer');?></th>
                <th class="text-right">
                    <?php echo CHtml::beginForm(array("admin/quotas/sa/new_answer/surveyid/{$oSurvey->getPrimaryKey()}"), 'post');?>
                    <?php echo CHtml::hiddenField('sid',$oSurvey->getPrimaryKey(), ['id'=> 'addForm_sid' ]);?>
                    <?php echo CHtml::hiddenField('action','quotas', ['id'=> 'addForm_action' ]);?>
                    <?php echo CHtml::hiddenField('quota_id',$oQuota->getPrimaryKey(), ['id'=> 'addForm_quota_id' ]);?>
                    <?php echo CHtml::hiddenField('subaction','new_answer', ['id'=> 'addForm_subaction' ]);?>
                    <?php echo CHtml::submitButton(gT("Add answer"),array(
                        'name'=>'submit',
                        'class'=>'quota_new btn btn-default',
                    ));?>
                    <?php echo CHtml::endForm();?>
                </th>
            </tr>
        </thead>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,7 +25,7 @@
                 <span><span class="fa fa-external-link"></span> <?php echo gT('Autoload URL:').' '.htmlentities($oQuota->mainLanguagesetting->quotals_url);?></span>
             <?php endif;?>
         </div>
-        <?php echo viewHelper::flatEllipsizeText($oQuota->name) ;?>
+        <?php //echo htmlentities(viewHelper::flatEllipsizeText($oQuota->name)) ;?>
     </div>
     <table class="table table-quota-items table-striped table-condensed" >
         <thead>
```
