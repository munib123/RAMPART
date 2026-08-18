# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4561_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4561_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 84-124 of the vulnerable file.


        $this->image_dir = 'co';
    }

    /**
     * AdminController::renderList() override.
     *
     * @see AdminController::renderList()
     */
    public function renderList()
    {
        $this->addRowAction('view');
        $this->addRowAction('edit');
        $this->addRowAction('delete');

        return parent::renderList();
    }

    public function renderView()
    {
        if (($id = Tools::getValue('id_attribute_group'))) {
            $this->table = 'attribute';
            $this->className = 'Attribute';
            $this->identifier = 'id_attribute';
            $this->position_identifier = 'id_attribute';
            $this->position_group_identifier = 'id_attribute_group';
            $this->list_id = 'attribute_values';
            $this->lang = true;

            $this->context->smarty->assign([
                'current' => self::$currentIndex . '&id_attribute_group=' . (int) $id . '&viewattribute_group',
            ]);

            if (!Validate::isLoadedObject($obj = new AttributeGroup((int) $id))) {
                $this->errors[] = $this->trans('An error occurred while updating the status for an object.', [], 'Admin.Catalog.Notification') .
                    ' <b>' . $this->table . '</b> ' .
                    $this->trans('(cannot load object)', [], 'Admin.Catalog.Notification');

                return;
            }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -101,7 +101,7 @@
 
     public function renderView()
     {
-        if (($id = Tools::getValue('id_attribute_group'))) {
+        if (($id = (int) Tools::getValue('id_attribute_group'))) {
             $this->table = 'attribute';
             $this->className = 'Attribute';
             $this->identifier = 'id_attribute';
@@ -617,7 +617,7 @@
 
             case 'view':
                 if (Tools::getIsset('viewattribute_group')) {
-                    if (($id = Tools::getValue('id_attribute_group'))) {
+                    if (($id = (int) Tools::getValue('id_attribute_group'))) {
                         if (Validate::isLoadedObject($obj = new AttributeGroup((int) $id))) {
                             $bread_extended[] = $obj->name[$this->context->employee->id_lang];
                         }
@@ -630,7 +630,7 @@
 
             case 'editAttributes':
                 if ($this->id_attribute) {
-                    if (($id = Tools::getValue('id_attribute_group'))) {
+                    if (($id = (int) Tools::getValue('id_attribute_group'))) {
                         if (Validate::isLoadedObject($obj = new AttributeGroup((int) $id))) {
                             $bread_extended[] = '<a href="' . Context::getContext()->link->getAdminLink('AdminAttributesGroups') . '&id_attribute_group=' . $id . '&viewattribute_group">' . $obj->name[$this->context->employee->id_lang] . '</a>';
                         }
@@ -742,7 +742,7 @@
             return;
         }
 
-        if (!Tools::getValue($this->identifier) && Tools::getValue('id_attribute') && !Tools::getValue('attributeOrderby')) {
+        if (!Tools::getValue($this->identifier) && (int) Tools::getValue('id_attribute') && !Tools::getValue('attributeOrderby')) {
             // Override var of Controller
             $this->table = 'attribute';
             $this->className = 'Attribute';
@@ -751,7 +751,7 @@
 
         /* set location with current index */
         if (Tools::getIsset('id_attribute_group') && Tools::getIsset('viewattribute_group')) {
-            self::$currentIndex = self::$currentIndex . '&id_attribute_group=' . Tools::getValue('id_attribute_group', 0) . '&viewattribute_group';
+            self::$currentIndex = self::$currentIndex . '&id_attribute_group=' . (int) Tools::getValue('id_attribute_group', 0) . '&viewattribute_group';
         }
 
         // If it's an attribute, load object Attribute()
```
