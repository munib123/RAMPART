# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 5401_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5401_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 755-795 of the vulnerable file.

            'columns'    => array(
                gt('ID#')   => 'id',
                gt('Title') => 'title',
                gt('Body')  => 'body'
            ),
        ));

        assign_to_template(array(
            'page'  => $page,
            'items' => $page->records
        ));
    }

    /**
     * rerank module items, called from ddrerank
     */
    public function manage_ranks() {
        $rank = 1;
        foreach ($this->params['rerank'] as $id) {
            $modelname = $this->params['model'];
            $obj = new $modelname($id);
            $obj->rank = $rank;
            $obj->save(false, true);
            $rank++;
        }

        if (!expJavascript::inAjaxAction())
            redirect_to($this->params['lastpage']);
    }

    /**
     * Configure the module
     */
    public function configure() {
        global $db;

        expHistory::set('editable', $this->params);
        $views = expTemplate::get_config_templates($this, $this->loc);

        // needed for aggregation list
        $pullable_modules = expModules::listInstalledControllers($this->baseclassname, $this->loc);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -772,7 +772,7 @@
         $rank = 1;
         foreach ($this->params['rerank'] as $id) {
             $modelname = $this->params['model'];
-            $obj = new $modelname($id);
+            $obj = new $modelname(intval($id));
             $obj->rank = $rank;
             $obj->save(false, true);
             $rank++;
```
