# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3285_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3285_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 2120-2160 of the vulnerable file.

            ORDER BY
                fv.visits DESC';

        $result = $this->_config->getDb()->query($query);
        $topten = [];
        $data = [];

        if ($result) {
            while ($row = $this->_config->getDb()->fetchObject($result)) {
                if ($this->groupSupport) {
                    if (!in_array($row->user_id, array(-1, $this->user)) || !in_array($row->group_id, $this->groups)) {
                        continue;
                    }
                } else {
                    if (!in_array($row->user_id, array(-1, $this->user))) {
                        continue;
                    }
                }

                $data['visits'] = (int)$row->visits;
                $data['question'] = $row->question;
                $data['date'] = $row->updated;
                $data['last_visit'] = $row->last_visit;

                $title = $row->question;
                $url = sprintf(
                    '%sindex.php?%saction=artikel&cat=%d&id=%d&artlang=%s',
                    $this->_config->getDefaultUrl(),
                    $sids,
                    $row->category_id,
                    $row->id,
                    $row->lang
                );
                $oLink = new PMF_Link($url, $this->_config);
                $oLink->itemTitle = $row->question;
                $oLink->tooltip = $title;
                $data['url'] = $oLink->toString();

                $topten[$row->id] = $data;

                if (count($topten) === $count) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2137,7 +2137,7 @@
                 }
 
                 $data['visits'] = (int)$row->visits;
-                $data['question'] = $row->question;
+                $data['question'] = PMF_Filter::filterVar($row->question, FILTER_SANITIZE_STRING);
                 $data['date'] = $row->updated;
                 $data['last_visit'] = $row->last_visit;
 
@@ -2246,7 +2246,7 @@
                 }
 
                 $data['date'] = $row->updated;
-                $data['question'] = $row->question;
+                $data['question'] = PMF_Filter::filterVar($row->question, FILTER_SANITIZE_STRING);
                 $data['answer'] = $row->content;
                 $data['visits'] = $row->visits;
 
@@ -2260,7 +2260,7 @@
                     $row->lang
                 );
                 $oLink = new PMF_Link($url, $this->_config);
-                $oLink->itemTitle = $row->question;
+                $oLink->itemTitle = $title;
                 $oLink->tooltip = $title;
                 $data['url'] = $oLink->toString();
 
```
