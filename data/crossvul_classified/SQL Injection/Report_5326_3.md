# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 5326_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5326_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 837-877 of the vulnerable file.


        //Set the needed config for the view
        $config['custom_message_product'] = $this->config['custom_message_product'];
        $config['minimum_gift_card_purchase'] = $this->config['minimum_gift_card_purchase'];
        $records = expSession::get('params');
        expSession::un_set('params');
        assign_to_template(array(
            'giftcards' => $giftcards,
            'config'    => $config,
            'records'   => $records
        ));
    }

    function show() {
        global $db, $order, $template, $user;

        expHistory::set('viewable', $this->params);
//        $classname = $db->selectValue('product', 'product_type', 'id=' . $this->params['id']);
//        $product   = new $classname($this->params['id'], true, true);

        $id = isset($this->params['title']) ? $this->params['title'] : $this->params['id'];
        $product = new product($id);
        $product_type = new $product->product_type($product->id);
        $product_type->title = expString::parseAndTrim($product_type->title, true);
        $product_type->image_alt_tag = expString::parseAndTrim($product_type->image_alt_tag, true);

        //if we're trying to view a child product directly, then we redirect to it's parent show view
        //bunk URL, no product found
        if (empty($product->id)) {
            redirect_to(array('controller' => 'notfound', 'action' => 'page_not_found', 'title' => $this->params['title']));
        }
        // we do not display child products by themselves
        if (!empty($product->parent_id)) {
            $product = new product($product->parent_id);
            redirect_to(array('controller' => 'store', 'action' => 'show', 'title' => $product->sef_url));
        }
        if ($product->active_type == 1) {
            $product_type->user_message = "This product is temporarily unavailable for purchase.";
        } elseif ($product->active_type == 2 && !$user->isAdmin()) {
            flash("error", $product->title . " " . gt("is currently unavailable."));
            expHistory::back();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -854,7 +854,7 @@
 //        $classname = $db->selectValue('product', 'product_type', 'id=' . $this->params['id']);
 //        $product   = new $classname($this->params['id'], true, true);
 
-        $id = isset($this->params['title']) ? $this->params['title'] : $this->params['id'];
+        $id = isset($this->params['title']) ? expString::escape($this->params['title']) : $this->params['id'];
         $product = new product($id);
         $product_type = new $product->product_type($product->id);
         $product_type->title = expString::parseAndTrim($product_type->title, true);
@@ -908,7 +908,7 @@
         //need to add a check here for child product and redirect to parent if hit directly by ID
         expHistory::set('viewable', $this->params);
 
-        $product = new product(addslashes($this->params['title']));
+        $product = new product(expString::escape($this->params['title']));
         $product_type = new $product->product_type($product->id);
         $product_type->title = expString::parseAndTrim($product_type->title, true);
         $product_type->image_alt_tag = expString::parseAndTrim($product_type->image_alt_tag, true);
@@ -952,7 +952,7 @@
 
         expHistory::set('viewable', $this->params);
         $product = new product();
-        $model = $product->find("first", 'model="' . $this->params['model'] . '"');
+        $model = $product->find("first", 'model="' . expString::escape($this->params['model']) . '"');
         //eDebug($model);
         $product_type = new $model->product_type($model->id);
         //eDebug($product_type);
@@ -973,7 +973,7 @@
         expHistory::set('viewable', $this->params);
 //        $parent = isset($this->params['cat']) ? $this->params['cat'] : expSession::get('catid');
         $catid = expSession::get('catid');
-        $parent = !empty($catid) ? $catid : (!empty($this->params['cat']) ? $this->params['cat'] : 0);
+        $parent = !empty($catid) ? $catid : (!empty($this->params['cat']) ? intval($this->params['cat']) : 0);
         $category = new storeCategory($parent);
         $categories = $category->getEcomSubcategories();
         $ancestors = $category->pathToNode();
@@ -1650,7 +1650,7 @@
 
     function searchByModelForm() {
         // get the search terms
-        $terms = $this->params['search_string'];
+        $terms = expString::escape($this->params['search_string']);
 
         $sql = "model like '%" . $terms . "%'";
 
@@ -1688,6 +1688,7 @@
         if (!($user->isAdmin())) $sql .= '(p.active_type=0 OR p.active_type=1) AND ';
 
         //if first character of search is a -, then we do a wild card, else from beginning
+        $this->params['query'] = expString::escape($this->params['query']);
         if ($this->params['query'][0] == '-') {
             $sql .= " p.model LIKE '%" . $this->params['query'];
         } else {
@@ -1709,6 +1710,7 @@
     public function search() {
         global $db, $user;
 
+        $this->params['query'] = expString::escape($this->params['query']);
         if (SAVE_SEARCH_QUERIES && INCLUDE_AJAX_SEARCH == 1) {  // only to add search query record
             $qry = trim($this->params['query']);
             if (!empty($qry)) {
@@ -1808,6 +1810,8 @@
      */
     public function searchNew() {
         global $db, $user;
+
+        $this->params['query'] = expString::escape($this->params['query']);
         //$this->params['query'] = str_ireplace('-','\-',$this->params['query']);
         $sql = "select DISTINCT(p.id) as id, p.title, model, sef_url, f.id as fileid, ";
         $sql .= "match (p.title,p.model,p.body) against ('" . $this->params['query'] . "*' IN BOOLEAN MODE) as relevance, ";
```
