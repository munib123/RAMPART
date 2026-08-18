# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 1702_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1702_0`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 5-45 of the vulnerable file.

App::uses('File', 'Utility');

/**
 * Templates Controller
 *
 * @property Template $Templates
 */

class TemplatesController extends AppController {
	public $components = array('Security' ,'RequestHandler');

	public $paginate = array(
			'limit' => 50,
			'order' => array(
					'Template.id' => 'desc'
			)
	);

	public function beforeFilter() { // TODO REMOVE
		parent::beforeFilter();
		$this->Security->unlockedActions = array('saveElementSorting', 'populateEventFromTemplate', 'uploadFile', 'deleteTemporaryFile');
	}
	
	public function fetchFormFromTemplate($id) {
		
	}
	
	public function index() {
		$conditions = array();
		if (!$this->_isSiteAdmin()) {
			$conditions['OR'] = array('org' => $this->Auth->user('org'), 'share' => true);
		}
		if (!$this->_isSiteAdmin()) {
			$this->paginate = Set::merge($this->paginate,array(
					'conditions' =>
					array("OR" => array(
							array('org' => $this->Auth->user('org')),
							array('share' => true),
			))));
		}
		$this->set('list', $this->paginate());
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -22,12 +22,9 @@
 
 	public function beforeFilter() { // TODO REMOVE
 		parent::beforeFilter();
-		$this->Security->unlockedActions = array('saveElementSorting', 'populateEventFromTemplate', 'uploadFile', 'deleteTemporaryFile');
-	}
-	
-	public function fetchFormFromTemplate($id) {
-		
-	}
+		$this->Security->unlockedActions = array('uploadFile', 'deleteTemporaryFile');
+	}
+	
 	
 	public function index() {
 		$conditions = array();
@@ -136,6 +133,7 @@
 	}
 	
 	public function add() {
+		if (!$this->userRole['perm_template']) throw new MethodNotAllowedException('You are not authorised to do that.');
 		if ($this->request->is('post')) {
 			unset($this->request->data['Template']['tagsPusher']);
 			$tags = $this->request->data['Template']['tags'];
@@ -332,7 +330,7 @@
 			}
 			
 			if (isset($this->request->data['Template']['attributes'])) {
-				$attributes = unserialize($this->request->data['Template']['attributes']);
+				$attributes = json_decode($this->request->data['Template']['attributes'], true);
 				$this->loadModel('Attribute');
 				$fails = 0;
 				foreach($attributes as $k => &$attribute) {
```
