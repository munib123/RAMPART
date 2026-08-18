# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 3625_2
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3625_2`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 233-273 of the vulnerable file.

            if(count($this->result)>0) {
                $count = 0;
                foreach ($this->result as $aRow)
                {
                    // make address (Location)
                    $addr = array();
                    if($aRow['s_address']!='' && $aRow['s_address']!=null) { $addr[] = $aRow['s_address']; };
                    if($aRow['s_city']!='' && $aRow['s_city']!=null) { $addr[] = $aRow['s_city']; };
                    if($aRow['s_zip']!='' && $aRow['s_zip']!=null) { $addr[] = $aRow['s_zip']; };
                    if($aRow['s_region']!='' && $aRow['s_region']!=null) { $addr[] = $aRow['s_region']; };
                    if($aRow['s_country']!='' && $aRow['s_country']!=null) { $addr[] = $aRow['s_country']; };
                    $address = implode(", ", $addr);
                    
                    $this->sOutput .= "[";
                    $this->sOutput .= '"<div style=\'width:10px;\'><input type=\'checkbox\' name=\'id[]\' value=\''.$aRow['pk_i_id'].'\' /></div>",';
                    
                    $title         =   mb_substr($aRow['s_title'], 0, 30, 'utf-8');
                    if($title != $aRow['s_title']) {
                        $title .= "...";
                    }
                    $this->sOutput .= '"'.addslashes(preg_replace('|\s+|',' ',$title)).' <br/>';
                    $this->sOutput .= '<div id=\'datatable_wrapper\'><div id=\'datatables_quick_edit\' ';
                    if($count % 2) {
                        $this->sOutput .= ' class=\'even\' ';
                    }else{
                        $this->sOutput .= ' class=\'odd\' ';
                    }
                    $this->sOutput .= ' style=\'position:absolute;\'>';
                    $this->sOutput .= '<a href=\''.osc_admin_base_url(true).'?page=comments&action=list&amp;id='.$aRow['pk_i_id'].'\'>'.  __('View comments') .'</a>';
                    $this->sOutput .= ' | <a href=\''.osc_admin_base_url(true).'?page=media&action=list&amp;id='. $aRow['pk_i_id'] .'\'>'. __('View media') .'</a>';
                    if(isset($aRow['b_active']) && ($aRow['b_active'] == 1)) {
                        $this->sOutput .= ' | <a href=\''.osc_admin_base_url(true).'?page=items&action=status&amp;id='. $aRow['pk_i_id'] .'&amp;value=INACTIVE\'>'. __('Deactivate') .'</a>';
                    } else if (isset($aRow['b_active']) && ($aRow['b_active'] == 0)) {
                        $this->sOutput .= ' | <a href=\''.osc_admin_base_url(true).'?page=items&action=status&amp;id='. $aRow['pk_i_id'] .'&amp;value=ACTIVE\'>'. __('Activate') .'</a>';
                    }
                    if(isset($aRow['b_enabled']) && ($aRow['b_enabled'] == 1)) {
                        $this->sOutput .= ' | <a href=\''.osc_admin_base_url(true).'?page=items&action=status&amp;id='. $aRow['pk_i_id'] .'&amp;value=DISABLE\'>'. __('Disable') .'</a>';
                    } else if (isset($aRow['b_enabled']) && ($aRow['b_enabled'] == 0)) {
                        $this->sOutput .= ' | <a href=\''.osc_admin_base_url(true).'?page=items&action=status&amp;id='. $aRow['pk_i_id'] .'&amp;value=ENABLE\'>'. __('Enable') .'</a>';
                    }
                    if(isset($aRow['b_premium']) && $aRow['b_premium']) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -250,7 +250,7 @@
                     if($title != $aRow['s_title']) {
                         $title .= "...";
                     }
-                    $this->sOutput .= '"'.addslashes(preg_replace('|\s+|',' ',$title)).' <br/>';
+                    $this->sOutput .= '"'.addslashes(osc_esc_html(preg_replace('|\s+|',' ',$title))).' <br/>';
                     $this->sOutput .= '<div id=\'datatable_wrapper\'><div id=\'datatables_quick_edit\' ';
                     if($count % 2) {
                         $this->sOutput .= ' class=\'even\' ';
@@ -293,12 +293,12 @@
                         $this->sOutput .= '</div></div>",';
                     }
                     
-                    $this->sOutput .= '"'.addslashes($aRow['s_user_name']).'",';
-                    $this->sOutput .= '"'.addslashes($aRow['s_category_name']).'",';
-                    $this->sOutput .= '"'.$aRow['s_country'].'",';
-                    $this->sOutput .= '"'.$aRow['s_region'].'",';
-                    $this->sOutput .= '"'.$aRow['s_city'].'",';
-                    $this->sOutput .= '"'.addslashes($aRow['dt_pub_date']).'"';
+                    $this->sOutput .= '"'.addslashes(osc_esc_html($aRow['s_user_name'])).'",';
+                    $this->sOutput .= '"'.addslashes(osc_esc_html($aRow['s_category_name'])).'",';
+                    $this->sOutput .= '"'.addslashes(osc_esc_html($aRow['s_country'])).'",';
+                    $this->sOutput .= '"'.addslashes(osc_esc_html($aRow['s_region'])).'",';
+                    $this->sOutput .= '"'.addslashes(osc_esc_html($aRow['s_city'])).'",';
+                    $this->sOutput .= '"'.addslashes(osc_esc_html($aRow['dt_pub_date'])).'"';
                     if($this->extraCols > 0) $this->sOutput .= ',';
 
                     if(isset($aRow['i_num_spam'])) {
```
