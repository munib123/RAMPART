# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2267_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2267_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 152-192 of the vulnerable file.

                    Widget::newInstance()->insert(
                        array(
                            's_location' => Params::getParam('location'),
                            'e_kind' => 'html',
                            's_description' => Params::getParam('description'),
                            's_content' => Params::getParam('content', false, false)
                        )
                    );
                    osc_add_flash_ok_message( _m('Widget added correctly'), 'admin');
                    $this->redirectTo( osc_admin_base_url(true) . "?page=appearance&action=widgets" );
                break;
                /* /widget */
                case('activate'):
                    osc_csrf_check();
                    osc_set_preference('theme', Params::getParam('theme'));
                    osc_add_flash_ok_message( _m('Theme activated correctly'), 'admin');
                    osc_run_hook("theme_activate", Params::getParam('theme'));
                    $this->redirectTo( osc_admin_base_url(true) . "?page=appearance" );
                break;
                case('render'):
                    $this->_exportVariableToView('file', osc_base_path() . Params::getParam("file"));
                    $this->doView('appearance/view.php');
                break;
                default:
                    if(Params::getParam('checkUpdated') != '') {
                        osc_admin_toolbar_update_themes(true);
                    }

                    $themes = WebThemes::newInstance()->getListThemes();

                    //preparing variables for the view
                    $this->_exportVariableToView("themes", $themes);

                    $this->doView('appearance/index.php');
                break;
            }
        }

        //hopefully generic...
        function doView($file)
        {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -169,7 +169,34 @@
                     $this->redirectTo( osc_admin_base_url(true) . "?page=appearance" );
                 break;
                 case('render'):
-                    $this->_exportVariableToView('file', osc_base_path() . Params::getParam("file"));
+                    if(Params::existParam('route')) {
+                        $routes = Rewrite::newInstance()->getRoutes();
+                        $rid = Params::getParam('route');
+                        $file = '../';
+                        if(isset($routes[$rid]) && isset($routes[$rid]['file'])) {
+                            $file = $routes[$rid]['file'];
+                        }
+                    } else {
+                        // DEPRECATED: Disclosed path in URL is deprecated, use routes instead
+                        // This will be REMOVED in 3.6
+                        $file = Params::getParam('file');
+                        // We pass the GET variables (in case we have somes)
+                        if(preg_match('|(.+?)\?(.*)|', $file, $match)) {
+                            $file = $match[1];
+                            if(preg_match_all('|&([^=]+)=([^&]*)|', urldecode('&'.$match[2].'&'), $get_vars)) {
+                                for($var_k=0;$var_k<count($get_vars[1]);$var_k++) {
+                                    Params::setParam($get_vars[1][$var_k], $get_vars[2][$var_k]);
+                                }
+                            }
+                        } else {
+                            $file = Params::getParam('file');
+                        };
+                    }
+
+                    if(strpos($file, '../')!==false || !file_exists(osc_base_path() . $file)) {
+                        osc_add_flash_warning_message(__('Error loading theme custom file'), 'admin');
+                    };
+                    $this->_exportVariableToView('file', osc_base_path() . $file);
                     $this->doView('appearance/view.php');
                 break;
                 default:
```
