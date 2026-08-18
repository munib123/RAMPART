# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 224_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `224_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 272-313 of the vulnerable file.

            $object->barcode		           = GETPOST('barcode');
            // Set barcode_type_xxx from barcode_type id
            $stdobject=new GenericObject($db);
    	    $stdobject->element='product';
            $stdobject->barcode_type=GETPOST('fk_barcode_type');
            $result=$stdobject->fetch_barcode();
            if ($result < 0)
            {
            	$error++;
            	$mesg='Failed to get bar code type information ';
            	setEventMessages($mesg.$stdobject->error, $mesg.$stdobject->errors, 'errors');
            }
            $object->barcode_type_code      = $stdobject->barcode_type_code;
            $object->barcode_type_coder     = $stdobject->barcode_type_coder;
            $object->barcode_type_label     = $stdobject->barcode_type_label;

            $object->description        	 = dol_htmlcleanlastbr(GETPOST('desc','none'));
            $object->url					 = GETPOST('url');
            $object->note_private          	 = dol_htmlcleanlastbr(GETPOST('note_private','none'));
            $object->note               	 = $object->note_private;   // deprecated
            $object->customcode              = GETPOST('customcode');
            $object->country_id              = GETPOST('country_id');
            $object->duration_value     	 = $duration_value;
            $object->duration_unit      	 = $duration_unit;
            $object->seuil_stock_alerte 	 = GETPOST('seuil_stock_alerte')?GETPOST('seuil_stock_alerte'):0;
            $object->desiredstock            = GETPOST('desiredstock')?GETPOST('desiredstock'):0;
            $object->canvas             	 = GETPOST('canvas');
            $object->weight             	 = GETPOST('weight');
            $object->weight_units       	 = GETPOST('weight_units');
            $object->length             	 = GETPOST('size');
            $object->length_units       	 = GETPOST('size_units');
            $object->width               	 = GETPOST('sizewidth');
            $object->height             	 = GETPOST('sizeheight');
	        $object->surface            	 = GETPOST('surface');
            $object->surface_units      	 = GETPOST('surface_units');
            $object->volume             	 = GETPOST('volume');
            $object->volume_units       	 = GETPOST('volume_units');
            $object->finished           	 = GETPOST('finished');
	        $object->fk_unit                 = GETPOST('units');

			$accountancy_code_sell 			 = GETPOST('accountancy_code_sell');
			$accountancy_code_sell_intra	 = GETPOST('accountancy_code_sell_intra');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -289,8 +289,8 @@
             $object->url					 = GETPOST('url');
             $object->note_private          	 = dol_htmlcleanlastbr(GETPOST('note_private','none'));
             $object->note               	 = $object->note_private;   // deprecated
-            $object->customcode              = GETPOST('customcode');
-            $object->country_id              = GETPOST('country_id');
+            $object->customcode              = GETPOST('customcode','alpha');
+            $object->country_id              = GETPOST('country_id','int');
             $object->duration_value     	 = $duration_value;
             $object->duration_unit      	 = $duration_unit;
             $object->seuil_stock_alerte 	 = GETPOST('seuil_stock_alerte')?GETPOST('seuil_stock_alerte'):0;
@@ -306,13 +306,13 @@
             $object->surface_units      	 = GETPOST('surface_units');
             $object->volume             	 = GETPOST('volume');
             $object->volume_units       	 = GETPOST('volume_units');
-            $object->finished           	 = GETPOST('finished');
-	        $object->fk_unit                 = GETPOST('units');
-
-			$accountancy_code_sell 			 = GETPOST('accountancy_code_sell');
-			$accountancy_code_sell_intra	 = GETPOST('accountancy_code_sell_intra');
-			$accountancy_code_sell_export	 = GETPOST('accountancy_code_sell_export');
-			$accountancy_code_buy 			 = GETPOST('accountancy_code_buy');
+            $object->finished           	 = GETPOST('finished','alpha');
+            $object->fk_unit                 = GETPOST('units','alpha');
+
+	        $accountancy_code_sell 			 = GETPOST('accountancy_code_sell','alpha');
+	        $accountancy_code_sell_intra	 = GETPOST('accountancy_code_sell_intra','alpha');
+	        $accountancy_code_sell_export	 = GETPOST('accountancy_code_sell_export','alpha');
+	        $accountancy_code_buy 			 = GETPOST('accountancy_code_buy','alpha');
 
 			if ($accountancy_code_sell <= 0) { $object->accountancy_code_sell = ''; } else { $object->accountancy_code_sell = $accountancy_code_sell; }
 			if ($accountancy_code_sell_intra <= 0) { $object->accountancy_code_sell_intra = ''; } else { $object->accountancy_code_sell_intra = $accountancy_code_sell_intra; }
@@ -385,11 +385,11 @@
                 	$object->note_private           = dol_htmlcleanlastbr(GETPOST('note_private','none'));
                     $object->note                   = $object->note_private;
     			}
-                $object->customcode             = GETPOST('customcode');
-                $object->country_id             = GETPOST('country_id');
-                $object->status                 = GETPOST('statut');
-                $object->status_buy             = GETPOST('statut_buy');
-                $object->status_batch	        = GETPOST('status_batch');
+                $object->customcode             = GETPOST('customcode','alpha');
+                $object->country_id             = GETPOST('country_id','int');
+                $object->status                 = GETPOST('statut','int');
+                $object->status_buy             = GETPOST('statut_buy','int');
+                $object->status_batch	        = GETPOST('status_batch','aZ09');
                 // removed from update view so GETPOST always empty
                 /*
                 $object->seuil_stock_alerte     = GETPOST('seuil_stock_alerte');
@@ -410,7 +410,7 @@
                 $object->surface_units          = GETPOST('surface_units');
                 $object->volume                 = GETPOST('volume');
                 $object->volume_units           = GETPOST('volume_units');
-                $object->finished               = GETPOST('finished');
+                $object->finished               = GETPOST('finished','alpha');
 
 	            $units = GETPOST('units', 'int');
 
@@ -437,10 +437,10 @@
     	        $object->barcode_type_coder     = $stdobject->barcode_type_coder;
     	        $object->barcode_type_label     = $stdobject->barcode_type_label;
 
-				$accountancy_code_sell 			 = GETPOST('accountancy_code_sell');
-				$accountancy_code_sell_intra	 = GETPOST('accountancy_code_sell_intra');
-				$accountancy_code_sell_export	 = GETPOST('accountancy_code_sell_export');
-				$accountancy_code_buy 			 = GETPOST('accountancy_code_buy');
+    	        $accountancy_code_sell 			 = GETPOST('accountancy_code_sell','alpha');
+    	        $accountancy_code_sell_intra	 = GETPOST('accountancy_code_sell_intra','alpha');
+    	        $accountancy_code_sell_export	 = GETPOST('accountancy_code_sell_export','alpha');
+    	        $accountancy_code_buy 			 = GETPOST('accountancy_code_buy','alpha');
 
 				if ($accountancy_code_sell <= 0) { $object->accountancy_code_sell = ''; } else { $object->accountancy_code_sell = $accountancy_code_sell; }
 				if ($accountancy_code_sell_intra <= 0) { $object->accountancy_code_sell_intra = ''; } else { $object->accountancy_code_sell_intra = $accountancy_code_sell_intra; }
@@ -1303,7 +1303,7 @@
             print '</td></tr>';
 
 			// Batch number managment
-			if ($conf->productbatch->enabled) 
+			if ($conf->productbatch->enabled)
 			{
 				if ($object->isProduct() || ! empty($conf->global->STOCK_SUPPORTS_SERVICES))
 				{
@@ -1723,7 +1723,7 @@
 			print '</td></tr>';
 
             // Batch number management (to batch)
-            if (! empty($conf->productbatch->enabled)) 
+            if (! empty($conf->productbatch->enabled))
             {
 				if ($object->isProduct() || ! empty($conf->global->STOCK_SUPPORTS_SERVICES))
 				{
```
