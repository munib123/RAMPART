# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4561_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4561_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 215-255 of the vulnerable file.

     * @return string
     */
    public function displayEnableLink($token, $id, $value, $active, $id_category = null, $id_product = null, $ajax = false)
    {
        $tpl_enable = $this->createTemplate('list_action_enable.tpl');
        $tpl_enable->assign([
            'ajax' => $ajax,
            'enabled' => (bool) $value,
            'url_enable' => $this->currentIndex . '&' . $this->identifier . '=' . $id . '&' . $active . $this->table . ($ajax ? '&action=' . $active . $this->table . '&ajax=' . (int) $ajax : '') .
                ((int) $id_category && (int) $id_product ? '&id_category=' . (int) $id_category : '') . ($this->page && $this->page > 1 ? '&page=' . (int) $this->page : '') . '&token=' . ($token != null ? $token : $this->token),
        ]);

        return $tpl_enable->fetch();
    }

    public function displayListContent()
    {
        if (isset($this->fields_list['position'])) {
            if ($this->position_identifier) {
                if (isset($this->position_group_identifier)) {
                    $position_group_identifier = Tools::getIsset($this->position_group_identifier) ? Tools::getValue($this->position_group_identifier) : $this->position_group_identifier;
                } else {
                    $position_group_identifier = (int) Tools::getValue('id_' . ($this->is_cms ? 'cms_' : '') . 'category', ($this->is_cms ? '1' : Category::getRootCategory()->id));
                }
            } else {
                $position_group_identifier = Category::getRootCategory()->id;
            }

            $positions = array_map(function ($elem) { return (int) ($elem['position']); }, $this->_list);
            sort($positions);
        }

        // key_to_get is used to display the correct product category or cms category after a position change
        $identifier = in_array($this->identifier, ['id_category', 'id_cms_category']) ? '_parent' : '';
        if ($identifier) {
            $key_to_get = 'id_' . ($this->is_cms ? 'cms_' : '') . 'category' . $identifier;
        }

        foreach ($this->_list as $index => $tr) {
            $id = null;
            if (isset($tr[$this->identifier])) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -232,7 +232,7 @@
         if (isset($this->fields_list['position'])) {
             if ($this->position_identifier) {
                 if (isset($this->position_group_identifier)) {
-                    $position_group_identifier = Tools::getIsset($this->position_group_identifier) ? Tools::getValue($this->position_group_identifier) : $this->position_group_identifier;
+                    $position_group_identifier = Tools::getIsset($this->position_group_identifier) ? (int) Tools::getValue($this->position_group_identifier) : $this->position_group_identifier;
                 } else {
                     $position_group_identifier = (int) Tools::getValue('id_' . ($this->is_cms ? 'cms_' : '') . 'category', ($this->is_cms ? '1' : Category::getRootCategory()->id));
                 }
```
