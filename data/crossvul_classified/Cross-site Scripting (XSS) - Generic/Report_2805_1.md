# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2805_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2805_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1585-1625 of the vulnerable file.

            return $this->faqRecord['title'];
        }

        $question = '';

        $query = sprintf(
            "SELECT
                thema AS question
            FROM
                %sfaqdata
            WHERE
                id = %d AND lang = '%s'",
            PMF_Db::getTablePrefix(),
            $id,
            $this->_config->getLanguage()->getLanguage()
            );
        $result = $this->_config->getDb()->query($query);

        if ($this->_config->getDb()->numRows($result) > 0) {
            while ($row = $this->_config->getDb()->fetchObject($result)) {
                $question = $row->question;
            }
        } else {
            $question = $this->pmf_lang['no_cats'];
        }

        return $question;
    }

    /**
     * Gets all revisions from a given record ID.
     *
     * @param int    $recordId   Record id
     * @param string $recordLang Record language
     *
     * @return array
     */
    public function getRevisionIds($recordId, $recordLang)
    {
        $revisionData = [];

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1602,7 +1602,7 @@
 
         if ($this->_config->getDb()->numRows($result) > 0) {
             while ($row = $this->_config->getDb()->fetchObject($result)) {
-                $question = $row->question;
+                $question = PMF_String::htmlspecialchars($row->question);
             }
         } else {
             $question = $this->pmf_lang['no_cats'];
```
