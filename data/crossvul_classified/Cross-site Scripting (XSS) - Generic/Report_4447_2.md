# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4447_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4447_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 89-129 of the vulnerable file.

            $this->addOrderHistory($dataHistory);
        }
    }

//Scort
    public function scopeSort($query, $sortBy = null, $sortOrder = 'desc')
    {
        $sortBy = $sortBy ?? 'sort';
        return $query->orderBy($sortBy, $sortOrder);
    }

    /**
     * Create new order
     * @param  [array] $dataOrder
     * @param  [array] $dataTotal
     * @param  [array] $arrCartDetail
     * @return [array]
     */
    public function createOrder($dataOrder, $dataTotal, $arrCartDetail)
    {
        try {
            DB::connection(SC_CONNECTION)->beginTransaction();
            $dataOrder = sc_clean($dataOrder);
            $dataOrder['domain'] = url('/');
            $uID = $dataOrder['customer_id'];
            $currency = $dataOrder['currency'];
            $exchange_rate = $dataOrder['exchange_rate'];

            //Insert order
            $order = ShopOrder::create($dataOrder);
            $orderID = $order->id;
            //End insert order

            //Insert order total
            foreach ($dataTotal as $key => $row) {
                array_walk($row, function (&$v, $k) {
                    return $v = sc_clean($v);
                    }
                );
                $row['order_id'] = $orderID;
                $row['created_at'] = date('Y-m-d H:i:s');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -106,9 +106,13 @@
      */
     public function createOrder($dataOrder, $dataTotal, $arrCartDetail)
     {
+        //Process escape
+        $dataOrder     = sc_clean($dataOrder);
+        $dataTotal     = sc_clean($dataTotal);
+        $arrCartDetail = sc_clean($arrCartDetail);
+
         try {
             DB::connection(SC_CONNECTION)->beginTransaction();
-            $dataOrder = sc_clean($dataOrder);
             $dataOrder['domain'] = url('/');
             $uID = $dataOrder['customer_id'];
             $currency = $dataOrder['currency'];
```
