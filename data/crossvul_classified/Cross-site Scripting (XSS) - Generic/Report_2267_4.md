# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2267_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2267_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 56-97 of the vulnerable file.

                if(Params::getParam('direction') == 'desc') {
                    $arg_date .= '&direction=asc';
                };
            }
            $arg_item = '&sort=attached_to';
            if(Params::getParam('sort') == 'attached_to') {
                if(Params::getParam('direction') == 'desc') {
                    $arg_item .= '&direction=asc';
                };
            }

            Rewrite::newInstance()->init();
            $page  = (int)Params::getParam('iPage');
            if($page==0) { $page = 1; };
            Params::setParam('iPage', $page);
            $url_base = preg_replace('|&direction=([^&]*)|', '', preg_replace('|&sort=([^&]*)|', '', osc_base_url().Rewrite::newInstance()->get_raw_request_uri()));

            $this->addColumn('bulkactions', '<input id="check_all" type="checkbox" />');
            $this->addColumn('file', __('File'));
            $this->addColumn('action', __('Action'));
            $this->addColumn('attached_to', '<a href="'.$url_base.$arg_item.'">'.__('Attached to').'</a>');
            $this->addColumn('date', '<a href="'.$url_base.$arg_date.'">'.__('Date').'</a>');

            $dummy = &$this;
            osc_run_hook("admin_media_table", $dummy);
        }
        
        private function processData($media)
        {
            if(!empty($media)) {
            
                foreach($media as $aRow) {
                    $row = array();

                    $row['bulkactions'] = '<input type="checkbox" name="id[]" value="' . $aRow['pk_i_id'] . '" />';
                    $row['file'] = '<div id="media_list_pic"><img src="' . osc_apply_filter('resource_path', osc_base_url() . $aRow['s_path']) . $aRow['pk_i_id'] . '_thumbnail.' . $aRow['s_extension'] . '" style="max-width: 60px; max-height: 60px;" /></div> <div id="media_list_filename">' . $aRow['s_content_type'];
                    $row['action'] = '<a onclick="return delete_dialog(\'' . $aRow['pk_i_id'] . '\');" >' . __('Delete') . '</a>';
                    $row['attached_to'] = '<a target="_blank" href="' . osc_item_url_ns($aRow['fk_i_item_id']) . '">item #' . $aRow['fk_i_item_id'] . '</a>';
                    $row['date'] = osc_format_date($aRow['dt_pub_date']);

                    $row = osc_apply_filter('media_processing_row', $row, $aRow);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -73,8 +73,8 @@
             $this->addColumn('bulkactions', '<input id="check_all" type="checkbox" />');
             $this->addColumn('file', __('File'));
             $this->addColumn('action', __('Action'));
-            $this->addColumn('attached_to', '<a href="'.$url_base.$arg_item.'">'.__('Attached to').'</a>');
-            $this->addColumn('date', '<a href="'.$url_base.$arg_date.'">'.__('Date').'</a>');
+            $this->addColumn('attached_to', '<a href="'.osc_esc_html($url_base.$arg_item).'">'.__('Attached to').'</a>');
+            $this->addColumn('date', '<a href="'.osc_esc_html($url_base.$arg_date).'">'.__('Date').'</a>');
 
             $dummy = &$this;
             osc_run_hook("admin_media_table", $dummy);
```
