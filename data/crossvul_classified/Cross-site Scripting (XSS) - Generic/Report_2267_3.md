# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2267_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2267_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 121-162 of the vulnerable file.

            $arg_expiration = '&sort=expiration';
            if(Params::getParam('sort') == 'expiration') {
                if(Params::getParam('direction') == 'desc') {
                    $arg_expiration .= '&direction=asc';
                };
            }

            Rewrite::newInstance()->init();
            $page  = (int)Params::getParam('iPage');
            if($page==0) { $page = 1; };
            Params::setParam('iPage', $page);
            $url_base = preg_replace('|&direction=([^&]*)|', '', preg_replace('|&sort=([^&]*)|', '', osc_base_url().Rewrite::newInstance()->get_raw_request_uri()));

            $this->addColumn('status-border', '');
            $this->addColumn('status', __('Status'));
            $this->addColumn('bulkactions', '<input id="check_all" type="checkbox" />');
            $this->addColumn('title', __('Title'));
            $this->addColumn('user', __('User'));
            $this->addColumn('category', __('Category'));
            $this->addColumn('location', __('Location'));
            $this->addColumn('date', '<a href="'.$url_base.$arg_date.'">'.__('Date').'</a>');
            $this->addColumn('expiration', '<a href="'.$url_base.$arg_expiration.'">'.__('Expiration date').'</a>');

            $dummy = &$this;
            osc_run_hook("admin_items_table", $dummy);
        }

        private function addTableHeaderReported()
        {

            Rewrite::newInstance()->init();
            $page  = (int)Params::getParam('iPage');
            if($page==0) { $page = 1; };
            Params::setParam('iPage', $page);
            $url_base = preg_replace('|&direction=([^&]*)|', '', preg_replace('|&sort=([^&]*)|', '', osc_base_url().Rewrite::newInstance()->get_raw_request_uri()));
            $arg_spam   = '&sort=spam'; $arg_bad    = '&sort=bad';
            $arg_rep    = '&sort=rep';  $arg_off    = '&sort=off';
            $arg_exp    = '&sort=exp';  $arg_date   = '&sort=date';
            $arg_expiration = '&sort=expiration';
            $sort       = Params::getParam("sort");
            $direction  = Params::getParam("direction");

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -138,8 +138,8 @@
             $this->addColumn('user', __('User'));
             $this->addColumn('category', __('Category'));
             $this->addColumn('location', __('Location'));
-            $this->addColumn('date', '<a href="'.$url_base.$arg_date.'">'.__('Date').'</a>');
-            $this->addColumn('expiration', '<a href="'.$url_base.$arg_expiration.'">'.__('Expiration date').'</a>');
+            $this->addColumn('date', '<a href="'.osc_esc_html($url_base.$arg_date).'">'.__('Date').'</a>');
+            $this->addColumn('expiration', '<a href="'.osc_esc_html($url_base.$arg_expiration).'">'.__('Expiration date').'</a>');
 
             $dummy = &$this;
             osc_run_hook("admin_items_table", $dummy);
@@ -197,13 +197,13 @@
             $this->addColumn('bulkactions', '<input id="check_all" type="checkbox" />');
             $this->addColumn('title', __('Title'));
             $this->addColumn('user', __('User'));
-            $this->addColumn('spam', '<a id="order_spam" href="'.$url_spam.'">'.__('Spam').'</a>');
-            $this->addColumn('bad', '<a id="order_bad" href="'.$url_bad.'">'.__('Misclassified').'</a>');
-            $this->addColumn('rep', '<a id="order_rep" href="'.$url_rep.'">'.__('Duplicated').'</a>');
-            $this->addColumn('exp', '<a id="order_exp" href="'.$url_exp.'">'.__('Expired').'</a>');
-            $this->addColumn('off', '<a id="order_off" href="'.$url_off.'">'.__('Offensive').'</a>');
-            $this->addColumn('date', '<a id="order_date" href="'.$url_date.'">'.__('Date').'</a>');
-            $this->addColumn('expiration', '<a id="order_expiration" href="'.$url_expiration.'">'.__('Expiration date').'</a>');
+            $this->addColumn('spam', '<a id="order_spam" href="'.osc_esc_html($url_spam).'">'.__('Spam').'</a>');
+            $this->addColumn('bad', '<a id="order_bad" href="'.osc_esc_html($url_bad).'">'.__('Misclassified').'</a>');
+            $this->addColumn('rep', '<a id="order_rep" href="'.osc_esc_html($url_rep).'">'.__('Duplicated').'</a>');
+            $this->addColumn('exp', '<a id="order_exp" href="'.osc_esc_html($url_exp).'">'.__('Expired').'</a>');
+            $this->addColumn('off', '<a id="order_off" href="'.osc_esc_html($url_off).'">'.__('Offensive').'</a>');
+            $this->addColumn('date', '<a id="order_date" href="'.osc_esc_html($url_date).'">'.__('Date').'</a>');
+            $this->addColumn('expiration', '<a id="order_expiration" href="'.osc_esc_html($url_expiration).'">'.__('Expiration date').'</a>');
 
             $dummy = &$this;
             osc_run_hook("admin_items_reported_table", $dummy);
```
