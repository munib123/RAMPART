# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 4091_0
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4091_0`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 55-95 of the vulnerable file.


        return (parent::install()
            && $this->registerHook('dashboardZoneTwo')
            && $this->registerHook('dashboardData')
            && $this->registerHook('actionObjectOrderAddAfter')
            && $this->registerHook('actionSearch')
        );
    }

    public function hookDashboardZoneTwo($params)
    {
        $this->context->smarty->assign(
            array(
                'DASHACTIVITY_CART_ACTIVE' => Configuration::get('DASHACTIVITY_CART_ACTIVE'),
                'DASHACTIVITY_VISITOR_ONLINE' => Configuration::get('DASHACTIVITY_VISITOR_ONLINE'),
                'DASHPRODUCT_NBR_SHOW_LAST_ORDER' => Configuration::get('DASHPRODUCT_NBR_SHOW_LAST_ORDER'),
                'DASHPRODUCT_NBR_SHOW_BEST_SELLER' => Configuration::get('DASHPRODUCT_NBR_SHOW_BEST_SELLER'),
                'DASHPRODUCT_NBR_SHOW_TOP_SEARCH' => Configuration::get('DASHPRODUCT_NBR_SHOW_TOP_SEARCH'),
                'date_from' => Tools::displayDate($params['date_from']),
                'date_to' => Tools::displayDate($params['date_to']),
                'dashproducts_config_form' => $this->renderConfigForm(),
            )
        );

        return $this->display(__FILE__, 'dashboard_zone_two.tpl');
    }

    public function hookDashboardData($params)
    {
        $table_recent_orders = $this->getTableRecentOrders();
        $table_best_sellers = $this->getTableBestSellers($params['date_from'], $params['date_to']);
        $table_most_viewed = $this->getTableMostViewed($params['date_from'], $params['date_to']);
        $table_top_10_most_search = $this->getTableTop10MostSearch($params['date_from'], $params['date_to']);

        //$table_top_5_search = $this->getTableTop5Search();
        return array(
            'data_table' => array(
                'table_recent_orders' => $table_recent_orders,
                'table_best_sellers' => $table_best_sellers,
                'table_most_viewed' => $table_most_viewed,
                'table_top_10_most_search' => $table_top_10_most_search,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -72,7 +72,7 @@
                 'DASHPRODUCT_NBR_SHOW_TOP_SEARCH' => Configuration::get('DASHPRODUCT_NBR_SHOW_TOP_SEARCH'),
                 'date_from' => Tools::displayDate($params['date_from']),
                 'date_to' => Tools::displayDate($params['date_to']),
-                'dashproducts_config_form' => $this->renderConfigForm(),
+                'dashproducts_config_form' => $this->getPermission('configure') ? $this->renderConfigForm() : null,
             )
         );
 
@@ -617,4 +617,44 @@
     {
         Tools::changeFileMTime($this->push_filename);
     }
+
+    /**
+     * Validate dashboard configuration
+     *
+     * @param array $config
+     *
+     * @return array
+     */
+    public function validateDashConfig(array $config)
+    {
+        $errors = [];
+        $possibleValues = [5, 10, 20, 50];
+        foreach (array_keys($this->getConfigFieldsValues()) as $fieldName) {
+            if (!isset($config[$fieldName]) || !in_array($config[$fieldName], $possibleValues)) {
+                $errors[$fieldName] = $this->trans('The %s field is invalid.', [$fieldName], 'Modules.Dashproducts.Admin');
+            }
+        }
+
+        return $errors;
+    }
+
+    /**
+     * Save dashboard configuration
+     *
+     * @param array $config
+     *
+     * @return bool determines if there are errors or not
+     */
+    public function saveDashConfig(array $config)
+    {
+        if (!$this->getPermission('configure')) {
+            return true;
+        }
+
+        foreach (array_keys($this->getConfigFieldsValues()) as $fieldName) {
+            Configuration::updateValue($fieldName, (int) $config[$fieldName]);
+        }
+
+        return false;
+    }
 }
```
