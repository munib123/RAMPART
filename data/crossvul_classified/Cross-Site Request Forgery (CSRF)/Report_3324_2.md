# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 3324_2
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3324_2`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 195-235 of the vulnerable file.

			$this->fields = plugman_adminArea::getPluginManagerFields();
			$this->fields['plugin_category']['writeParms']['optArray'] = e107::getPlug()->getCategoryList(); // array('plugin_category_0','plugin_category_1', 'plugin_category_2'); // Example Drop-down array.

			unset($this->fields['plugin_category']['writeParms']['optArray']['menu']);
			unset($this->fields['plugin_category']['writeParms']['optArray']['about']);

			parent:: __construct($request, $response, $params);

		}


		public function init()
		{

			if(!e_QUERY)
			{
				e107::getPlug()->clearCache();
			}



			if($this->getMode()=== 'avail')
			{
				$this->listQry  = "SELECT * FROM `#plugin` WHERE plugin_installflag = 0 AND plugin_category != 'menu'  ";
			}

			// Set drop-down values (if any).

		}

		// Modify the list data.
        public function ListObserver()
        {
            parent::ListObserver();

	        $this->setPlugData();
        }

		private function setPlugData()
		{
			   $tree = $this->getTreeModel();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -212,7 +212,6 @@
 			}
 
 
-
 			if($this->getMode()=== 'avail')
 			{
 				$this->listQry  = "SELECT * FROM `#plugin` WHERE plugin_installflag = 0 AND plugin_category != 'menu'  ";
@@ -397,7 +396,10 @@
 
 			$post = e107::getParser()->filter($_POST);
 
-
+			if(empty($_POST['e-token']))
+			{
+				return false;
+			}
 
 		//	$id = e107::getPlugin
 
@@ -811,13 +813,15 @@
 			*/
              //   $frm->admin_button($name, $value, $action = 'submit', $label = '', $options = array());
 
-			$text .= "</div>
+
+
+			$text .= "<input type='hidden' name='e-token' value='".e_TOKEN."' /></div>
 			</fieldset>
 			</form>
 			";
 
 			return $text;
-			e107::getRender()->tablerender(EPL_ADLAN_63.SEP.$tp->toHtml($plug_vars['@attributes']['name'], "", "defs,emotes_off, no_make_clickable"),$mes->render(). $text);
+		//	e107::getRender()->tablerender(EPL_ADLAN_63.SEP.$tp->toHtml($plug_vars['@attributes']['name'], "", "defs,emotes_off, no_make_clickable"),$mes->render(). $text);
 
 		}
 	/*
```
