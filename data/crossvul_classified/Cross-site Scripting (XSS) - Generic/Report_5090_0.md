# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5090_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5090_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 2771-2811 of the vulnerable file.

                // Results from a "SELECT" statement -> builds the
                // WHERE clause to use in links (a unique key if possible)
                /**
                 * @todo $where_clause could be empty, for example a table
                 *       with only one field and it's a BLOB; in this case,
                 *       avoid to display the delete and edit links
                 */
                list($where_clause, $clause_is_unique, $condition_array)
                    = Util::getUniqueCondition(
                        $dt_result, // handle
                        $this->__get('fields_cnt'), // fields_cnt
                        $this->__get('fields_meta'), // fields_meta
                        $row, // row
                        false, // force_unique
                        $this->__get('table'), // restrict_to_table
                        $analyzed_sql_results // analyzed_sql_results
                    );
                $whereClauseMap[$row_no][$this->__get('table')] = $where_clause;
                $this->__set('whereClauseMap', $whereClauseMap);

                $where_clause_html = urlencode($where_clause);

                // 1.2.1 Modify link(s) - update row case
                if ($displayParts['edit_lnk'] == self::UPDATE_ROW) {

                    list($edit_url, $copy_url, $edit_str, $copy_str,
                        $edit_anchor_class)
                            = $this->_getModifiedLinks(
                                $where_clause,
                                $clause_is_unique, $url_sql_query
                            );

                } // end if (1.2.1)

                // 1.2.2 Delete/Kill link(s)
                list($del_url, $del_str, $js_conf)
                    = $this->_getDeleteAndKillLinks(
                        $where_clause, $clause_is_unique,
                        $url_sql_query, $displayParts['del_lnk'],
                        $row
                    );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2788,7 +2788,7 @@
                 $whereClauseMap[$row_no][$this->__get('table')] = $where_clause;
                 $this->__set('whereClauseMap', $whereClauseMap);
 
-                $where_clause_html = urlencode($where_clause);
+                $where_clause_html = htmlspecialchars($where_clause);
 
                 // 1.2.1 Modify link(s) - update row case
                 if ($displayParts['edit_lnk'] == self::UPDATE_ROW) {
```
