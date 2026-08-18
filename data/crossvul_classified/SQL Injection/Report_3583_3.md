# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3583_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3583_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 79-119 of the vulnerable file.

                break;
                case 'edit_widget':
                    $id = Params::getParam('id');
                    
                    $widget = Widget::newInstance()->findByPrimaryKey($id);
                    $this->_exportVariableToView("widget", $widget);

                    $this->doView('appearance/add_widget.php');
                break;
                case 'delete_widget':
                    Widget::newInstance()->delete(
                        array('pk_i_id' => Params::getParam('id') )
                    );
                    osc_add_flash_ok_message( _m('Widget removed correctly'), 'admin');
                    $this->redirectTo( osc_admin_base_url(true) . "?page=appearance&action=widgets" );
                break;
                case 'edit_widget_post':
                    $res = Widget::newInstance()->update(
                        array(
                            's_description' => Params::getParam('description')
                            ,'s_content' => Params::getParam('content')
                        ),
                        array('pk_i_id' => Params::getParam('id') )
                    );

                    if( $res ) {
                        osc_add_flash_ok_message( _m('Widget updated correctly'), 'admin');
                    } else {
                        osc_add_flash_ok_message( _m('Widget cannot be updated correctly'), 'admin');
                    }
                    $this->redirectTo( osc_admin_base_url(true) . "?page=appearance&action=widgets" );
                    break;
                case 'add_widget_post':
                    Widget::newInstance()->insert(
                        array(
                            's_location' => Params::getParam('location')
                            ,'e_kind' => 'html'
                            ,'s_description' => Params::getParam('description')
                            ,'s_content' => Params::getParam('content')
                        )
                    );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -96,7 +96,7 @@
                     $res = Widget::newInstance()->update(
                         array(
                             's_description' => Params::getParam('description')
-                            ,'s_content' => Params::getParam('content')
+                            ,'s_content' => Params::getParam('content', false, false)
                         ),
                         array('pk_i_id' => Params::getParam('id') )
                     );
@@ -114,7 +114,7 @@
                             's_location' => Params::getParam('location')
                             ,'e_kind' => 'html'
                             ,'s_description' => Params::getParam('description')
-                            ,'s_content' => Params::getParam('content')
+                            ,'s_content' => Params::getParam('content', false, false)
                         )
                     );
                     osc_add_flash_ok_message( _m('Widget added correctly'), 'admin');
```
