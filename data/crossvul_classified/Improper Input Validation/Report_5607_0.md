# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 5607_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5607_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 1978-2019 of the vulnerable file.

				} else {
					$t_search_max = PHP_INT_MAX;
				}
				// Note: no need to test negative values, '-' sign has been removed
				if( $t_search_term <= $t_search_max ) {
					$c_search_int = (int) $t_search_term;
					$t_textsearch_where_clause .= " OR $t_bug_table.id = " . db_param();
					$t_textsearch_where_clause .= " OR $t_bugnote_table.id = " . db_param();
					$t_where_params[] = $c_search_int;
					$t_where_params[] = $c_search_int;
				}
			}

			$t_textsearch_where_clause .= ' )';
			$t_first = false;
		}
		$t_textsearch_where_clause .= ' )';

		# add text query elements to arrays
		if ( !$t_first ) {
			$t_from_clauses[] = "$t_bug_text_table";
			$t_where_clauses[] = "$t_bug_table.bug_text_id = $t_bug_text_table.id";
			$t_where_clauses[] = $t_textsearch_where_clause;
			$t_join_clauses[] = " LEFT JOIN $t_bugnote_table ON $t_bug_table.id = $t_bugnote_table.bug_id";
			$t_join_clauses[] = " LEFT JOIN $t_bugnote_text_table ON $t_bugnote_table.bugnote_text_id = $t_bugnote_text_table.id";
		}
	}

	# End text search

	# Determine join operator
	if ( $t_filter[FILTER_PROPERTY_MATCH_TYPE] == FILTER_MATCH_ANY )
		$t_join_operator = ' OR ';
	else
		$t_join_operator = ' AND ';

	log_event(LOG_FILTERING, 'Join operator : ' . $t_join_operator);

	$t_from_clauses[] = $t_project_table;
	$t_from_clauses[] = $t_bug_table;

	$t_query_clauses['select'] = $t_select_clauses;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1995,11 +1995,10 @@
 
 		# add text query elements to arrays
 		if ( !$t_first ) {
-			$t_from_clauses[] = "$t_bug_text_table";
-			$t_where_clauses[] = "$t_bug_table.bug_text_id = $t_bug_text_table.id";
+			$t_join_clauses[] = "JOIN $t_bug_text_table ON $t_bug_table.bug_text_id = $t_bug_text_table.id";
+			$t_join_clauses[] = "LEFT JOIN $t_bugnote_table ON $t_bug_table.id = $t_bugnote_table.bug_id";
+			$t_join_clauses[] = "LEFT JOIN $t_bugnote_text_table ON $t_bugnote_table.bugnote_text_id = $t_bugnote_text_table.id";
 			$t_where_clauses[] = $t_textsearch_where_clause;
-			$t_join_clauses[] = " LEFT JOIN $t_bugnote_table ON $t_bug_table.id = $t_bugnote_table.bug_id";
-			$t_join_clauses[] = " LEFT JOIN $t_bugnote_text_table ON $t_bugnote_table.bugnote_text_id = $t_bugnote_text_table.id";
 		}
 	}
 
```
