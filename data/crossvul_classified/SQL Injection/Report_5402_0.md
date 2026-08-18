# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 5402_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5402_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 41-81 of the vulnerable file.

        'rss',
        'tags',
        'twitter',
    );  // all options: ('aggregation','categories','comments','ealerts','facebook','files','pagination','rss','tags','twitter',)

    static function displayname() { return gt("Search Form"); }
    static function description() { return gt("Add a form to allow users to search for content on your website."); }
    static function hasSources() { return false; }
    static function hasContent() { return false; }

    public function search()
    {
        global $router;

        $terms = $this->params['search_string'];

        // If magic quotes is on and the user uses modifiers like " (quotes) they get escaped. We don't want that in this case.
        if (get_magic_quotes_gpc()) {
            $terms = stripslashes($terms);
        }
        $terms = htmlspecialchars($terms);

        if ($router->current_url == substr(URL_FULL, 0, -1)) {  // give us a user friendly url
            unset($router->params['int']);
//            unset($router->params['src']);
//            $router->params['src'] = '1';
            redirect_to($router->params);
        }

        $search = new search();

        $page = new expPaginator(array(
//            'model'=>'search',
            'records'=>$search->getSearchResults($terms, !empty($this->config['only_best']), 0, !empty($this->config['eventlimit']) ? $this->config['eventlimit'] : null),
            //'sql'=>$sql,
            'limit'=>(isset($this->config['limit']) && $this->config['limit'] != '') ? $this->config['limit'] : 10,
            'order'=>'score',
            'dir'=>'DESC',
            'page' => (isset($this->params['page']) ? $this->params['page'] : 1),
            'dontsortwithincat'=>true,
            'controller' => $this->params['controller'],
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -58,7 +58,7 @@
         if (get_magic_quotes_gpc()) {
             $terms = stripslashes($terms);
         }
-        $terms = htmlspecialchars($terms);
+        $terms = expString::escape(htmlspecialchars($terms));
 
         if ($router->current_url == substr(URL_FULL, 0, -1)) {  // give us a user friendly url
             unset($router->params['int']);
```
