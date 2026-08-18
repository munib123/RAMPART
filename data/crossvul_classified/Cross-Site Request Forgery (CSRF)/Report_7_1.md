# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 7_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `7_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 494-534 of the vulnerable file.


    public function getTypeIcon()
    {
        if (empty($this->sTypeIcon)) {
            $this->sTypeIcon = (Template::isStandardTemplate($this->template->name)) ?gT("Core theme") : gT("User theme");
        }
        return $this->sTypeIcon;
    }


    public function getButtons()
    {
        $sEditorUrl = Yii::app()->getController()->createUrl('admin/themes/sa/view', array("templatename"=>$this->template_name));
        if (App()->getController()->action->id == "surveysgroups") {
            $gisd = Yii::app()->request->getQuery('id', null);
            $sOptionUrl    = Yii::app()->getController()->createUrl('admin/themeoptions/sa/updatesurveygroup', array("id"=>$this->id, "gsid"=>$gisd));
        } else {
            $sOptionUrl    = Yii::app()->getController()->createUrl('admin/themeoptions/sa/update', array("id"=>$this->id));
        }

        $sUninstallUrl = Yii::app()->getController()->createUrl('admin/themeoptions/sa/uninstall/', array("templatename"=>$this->template_name));

        $sEditorLink = "<a
            id='template_editor_link_".$this->template_name."'
            href='".$sEditorUrl."'
            class='btn btn-default btn-block'>
                <span class='icon-templates'></span>
                ".gT('Theme editor')."
            </a>";

            //


        $OptionLink = '';

        if ($this->hasOptionPage) {
            $OptionLink .= "<a
                id='template_options_link_".$this->template_name."'
                href='".$sOptionUrl."'
                class='btn btn-default btn-block'>
                    <span class='fa fa-tachometer'></span>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -511,7 +511,7 @@
             $sOptionUrl    = Yii::app()->getController()->createUrl('admin/themeoptions/sa/update', array("id"=>$this->id));
         }
 
-        $sUninstallUrl = Yii::app()->getController()->createUrl('admin/themeoptions/sa/uninstall/', array("templatename"=>$this->template_name));
+        $sUninstallUrl = Yii::app()->getController()->createUrl('admin/themeoptions/sa/uninstall/');
 
         $sEditorLink = "<a
             id='template_editor_link_".$this->template_name."'
@@ -538,7 +538,9 @@
 
         $sUninstallLink = '<a
             id="remove_fromdb_link_'.$this->template_name.'"
-            data-href="'.$sUninstallUrl.'"
+            data-ajax-url="'.$sUninstallUrl.'"
+            data-post=\'{ "templatename": "'.$this->template_name.'" }\'
+            data-gridid = "yw0"
             data-target="#confirmation-modal"
             data-toggle="modal"
             data-message="'.gT('This will delete all the specific configurations of this theme.').'<br>'.gT('Do you want to continue?').'"
```
