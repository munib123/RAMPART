# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 4572_0
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4572_0`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 39-79 of the vulnerable file.

        $this->addRowAction('delete');
        $this->_orderWay = 'DESC';

        parent::__construct();

        $this->bulk_actions = array('delete' => array('text' => $this->trans('Delete selected', array(), 'Admin.Actions'), 'icon' => 'icon-trash', 'confirm' => $this->trans('Delete selected items?', array(), 'Admin.Notifications.Warning')));

        $this->fields_list = array(
            'id_cart_rule' => array('title' => $this->trans('ID', array(), 'Admin.Global'), 'align' => 'center', 'class' => 'fixed-width-xs'),
            'name' => array('title' => $this->trans('Name', array(), 'Admin.Global')),
            'priority' => array('title' => $this->trans('Priority', array(), 'Admin.Global'), 'align' => 'center', 'class' => 'fixed-width-xs'),
            'code' => array('title' => $this->trans('Code', array(), 'Admin.Global'), 'class' => 'fixed-width-sm'),
            'quantity' => array('title' => $this->trans('Quantity', array(), 'Admin.Catalog.Feature'), 'align' => 'center', 'class' => 'fixed-width-xs'),
            'date_to' => array('title' => $this->trans('Expiration date', array(), 'Admin.Catalog.Feature'), 'type' => 'datetime', 'class' => 'fixed-width-lg'),
            'active' => array('title' => $this->trans('Status', array(), 'Admin.Global'), 'active' => 'status', 'type' => 'bool', 'align' => 'center', 'class' => 'fixed-width-xs', 'orderby' => false),
        );
    }

    public function ajaxProcessLoadCartRules()
    {
        $type = $token = $search = '';
        $limit = $count = $id_cart_rule = 0;
        if (Tools::getIsset('limit')) {
            $limit = Tools::getValue('limit');
        }

        if (Tools::getIsset('type')) {
            $type = Tools::getValue('type');
        }

        if (Tools::getIsset('count')) {
            $count = Tools::getValue('count');
        }

        if (Tools::getIsset('id_cart_rule')) {
            $id_cart_rule = Tools::getValue('id_cart_rule');
        }

        if (Tools::getIsset('search')) {
            $search = Tools::getValue('search');
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -56,6 +56,10 @@
 
     public function ajaxProcessLoadCartRules()
     {
+        if (!$this->access('view')) {
+            return die(json_encode(array('error' => 'You do not have the right permission')));
+        }
+
         $type = $token = $search = '';
         $limit = $count = $id_cart_rule = 0;
         if (Tools::getIsset('limit')) {
```
