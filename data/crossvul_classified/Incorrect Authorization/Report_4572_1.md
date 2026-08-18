# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 4572_1
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4572_1`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 612-652 of the vulnerable file.

                    ? Configuration::get('CONF_' . strtoupper($order['carrier_reference']) . '_SHIP')
                    : Configuration::get('CONF_' . strtoupper($order['carrier_reference']) . '_SHIP_OVERSEAS')
                ) / 100;

            // Tally up these fees
            if ($granularity == 'day') {
                if (!isset($expenses[strtotime($order['date'])])) {
                    $expenses[strtotime($order['date'])] = 0;
                }
                $expenses[strtotime($order['date'])] += $flat_fees + $var_fees + $shipping_fees;
            } else {
                $expenses += $flat_fees + $var_fees + $shipping_fees;
            }
        }

        return $expenses;
    }

    public function displayAjaxGetKpi()
    {
        $currency = new Currency(Configuration::get('PS_CURRENCY_DEFAULT'));
        $tooltip = null;
        switch (Tools::getValue('kpi')) {
            case 'conversion_rate':
                $visitors = AdminStatsController::getVisits(
                    true,
                    date('Y-m-d', strtotime('-31 day')),
                    date('Y-m-d', strtotime('-1 day')),
                    false /*'day'*/
                );
                $orders = AdminStatsController::getOrders(
                    date('Y-m-d', strtotime('-31 day')),
                    date('Y-m-d', strtotime('-1 day')),
                    false /*'day'*/
                );

                // $data = array();
                // $from = strtotime(date('Y-m-d 00:00:00', strtotime('-31 day')));
                // $to = strtotime(date('Y-m-d 23:59:59', strtotime('-1 day')));
                // for ($date = $from; $date <= $to; $date = strtotime('+1 day', $date))
                // if (isset($visitors[$date]) && $visitors[$date])
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -629,6 +629,10 @@
 
     public function displayAjaxGetKpi()
     {
+        if (!$this->access('view')) {
+            return die(json_encode(array('error' => 'You do not have the right permission')));
+        }
+
         $currency = new Currency(Configuration::get('PS_CURRENCY_DEFAULT'));
         $tooltip = null;
         switch (Tools::getValue('kpi')) {
@@ -1039,6 +1043,10 @@
      */
     public function displayAjaxGraphDraw()
     {
+        if (!$this->access('view')) {
+            return die(json_encode(array('error' => 'You do not have the right permission')));
+        }
+
         $module = Tools::getValue('module');
         $render = Tools::getValue('render');
         $type = Tools::getValue('type');
@@ -1071,6 +1079,10 @@
      */
     public function displayAjaxGraphGrid()
     {
+        if (!$this->access('view')) {
+            return die(json_encode(array('error' => 'You do not have the right permission')));
+        }
+
         $module = Tools::getValue('module');
         $render = Tools::getValue('render');
         $type = Tools::getValue('type');
```
