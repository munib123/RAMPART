# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4564_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4564_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 98-138 of the vulnerable file.

     */
    protected function setTypeValue()
    {
        $this->table = 'feature_value';
        $this->className = 'FeatureValue';
        $this->identifier = 'id_feature_value';
    }

    /**
     * Change object type to feature (use when processing a feature).
     */
    protected function setTypeFeature()
    {
        $this->table = 'feature';
        $this->className = 'Feature';
        $this->identifier = 'id_feature';
    }

    public function renderView()
    {
        if (($id = Tools::getValue('id_feature'))) {
            $this->setTypeValue();
            $this->list_id = 'feature_value';
            $this->lang = true;

            // Action for list
            $this->addRowAction('edit');
            $this->addRowAction('delete');

            if (!Validate::isLoadedObject($obj = new Feature((int) $id))) {
                $this->errors[] = $this->trans('An error occurred while updating the status for an object.', array(), 'Admin.Notifications.Error') . ' <b>' . $this->table . '</b> ' . $this->trans('(cannot load object)', array(), 'Admin.Notifications.Error');

                return;
            }

            $this->feature_name = $obj->name;
            $this->toolbar_title = $this->feature_name[$this->context->employee->id_lang];
            $this->fields_list = array(
                'id_feature_value' => array(
                    'title' => $this->trans('ID', array(), 'Admin.Global'),
                    'align' => 'center',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -115,7 +115,7 @@
 
     public function renderView()
     {
-        if (($id = Tools::getValue('id_feature'))) {
+        if (($id = (int) Tools::getValue('id_feature'))) {
             $this->setTypeValue();
             $this->list_id = 'feature_value';
             $this->lang = true;
@@ -299,7 +299,7 @@
 
             case 'editFeatureValue':
                 if (Tools::getValue('id_feature_value')) {
-                    if (($id = Tools::getValue('id_feature'))) {
+                    if (($id = (int) Tools::getValue('id_feature'))) {
                         if (Validate::isLoadedObject($obj = new Feature((int) $id))) {
                             $bread_extended[] = '<a href="' . Context::getContext()->link->getAdminLink('AdminFeatures') . '&id_feature=' . $id . '&viewfeature">' . $obj->name[$this->context->employee->id_lang] . '</a>';
                         }
```
