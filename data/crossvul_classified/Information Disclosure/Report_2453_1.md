# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 2453_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2453_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 14-54 of the vulnerable file.

    public $belongsTo = array(
            'SharingGroup' => array(
                    'className' => 'SharingGroup',
                    'foreignKey' => 'sharing_group_id',
            ),
            'Tag' => array(
                    'className' => 'Tag',
                    'foreignKey' => 'tag_id',
            )
    );

    public $validate = array(
        'url' => array( // TODO add extra validation to refuse multiple time the same url from the same org
            'rule' => array('urlOrExistingFilepath')
        ),
        'provider' => 'valueNotEmpty',
        'name' => 'valueNotEmpty',
        'event_id' => array(
            'rule' => array('numeric'),
            'message' => 'Please enter a numeric event ID or leave this field blank.',
        )
    );

    // currently we only have an internal name and a display name, but later on we can expand this with versions, default settings, etc
    public $feed_types = array(
        'misp' => array(
            'name' => 'MISP Feed'
        ),
        'freetext' => array(
            'name' => 'Freetext Parsed Feed'
        ),
        'csv' => array(
            'name' => 'Simple CSV Parsed Feed'
        )
    );

    public function urlOrExistingFilepath($fields)
    {
        if ($this->isFeedLocal($this->data)) {
            if ($this->data['Feed']['source_format'] == 'misp') {
                if (!is_dir($this->data['Feed']['url'])) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,6 +31,10 @@
         'event_id' => array(
             'rule' => array('numeric'),
             'message' => 'Please enter a numeric event ID or leave this field blank.',
+        ),
+        'input_source' => array(
+            'rule' => 'validateInputSource',
+            'message' => ''
         )
     );
 
@@ -46,6 +50,27 @@
             'name' => 'Simple CSV Parsed Feed'
         )
     );
+
+    public function validateInputSource($fields)
+    {
+        if (!empty($this->data['Feed']['input_source'])) {
+            $localAllowed = empty(Configure::read('Security.disable_local_feed_access'));
+            $validOptions = array('network');
+            if ($localAllowed) {
+                $validOptions[] = 'local';
+            }
+            if (!in_array($this->data['Feed']['input_source'], $validOptions)) {
+                return __(
+                    'Invalid input source. The only valid options are %s. %s',
+                    implode(', ', $validOptions),
+                    (!$localAllowed && $this->data['Feed']['input_source'] === 'local') ?
+                    __('Security.disable_local_feed_access is currently enabled, local feeds are thereby not allowed.') :
+                    ''
+                );
+            }
+        }
+        return true;
+    }
 
     public function urlOrExistingFilepath($fields)
     {
```
