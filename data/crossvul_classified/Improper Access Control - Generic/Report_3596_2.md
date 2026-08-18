# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 3596_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3596_2`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 539-580 of the vulnerable file.

					break;
				case BUG_ADD_RELATIONSHIP:
					$t_note = lang_get( 'relationship_added' );
					$t_change = relationship_get_description_for_history( $p_old_value ) . ' ' . bug_format_id( $p_new_value );
					break;
				case BUG_REPLACE_RELATIONSHIP:
					$t_note = lang_get( 'relationship_replaced' );
					$t_change = relationship_get_description_for_history( $p_old_value ) . ' ' . bug_format_id( $p_new_value );
					break;
				case BUG_DEL_RELATIONSHIP:
					$t_note = lang_get( 'relationship_deleted' );

					# Fix for #7846: There are some cases where old value is empty, this may be due to an old bug.
					if( !is_blank( $p_old_value ) && $p_old_value > 0 ) {
						$t_change = relationship_get_description_for_history( $p_old_value ) . ' ' . bug_format_id( $p_new_value );
					} else {
						$t_change = bug_format_id( $p_new_value );
					}
					break;
				case BUG_CLONED_TO:
					$t_note = lang_get( 'bug_cloned_to' );
					$t_change = bug_format_id( $p_new_value );
					break;
				case BUG_CREATED_FROM:
					$t_note = lang_get( 'bug_created_from' );
					$t_change = bug_format_id( $p_new_value );
					break;
				case TAG_ATTACHED:
					$t_note = lang_get( 'tag_history_attached' ) . ': ' . $p_old_value;
					break;
				case TAG_DETACHED:
					$t_note = lang_get( 'tag_history_detached' ) . ': ' . $p_old_value;
					break;
				case TAG_RENAMED:
					$t_note = lang_get( 'tag_history_renamed' );
					$t_change = $p_old_value . ' => ' . $p_new_value;
					break;
				case BUG_REVISION_DROPPED:
					$t_note = lang_get( 'bug_revision_dropped_history' ) . ': ' . bug_revision_get_type_name( $p_new_value ) . ': ' . $p_old_value;
					break;
				case BUGNOTE_REVISION_DROPPED:
					$t_note = lang_get( 'bugnote_revision_dropped_history' ) . ': ' . $p_new_value . ': ' . $p_old_value;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -556,12 +556,10 @@
 					}
 					break;
 				case BUG_CLONED_TO:
-					$t_note = lang_get( 'bug_cloned_to' );
-					$t_change = bug_format_id( $p_new_value );
+					$t_note = lang_get( 'bug_cloned_to' ) . ': ' . bug_format_id( $p_new_value );
 					break;
 				case BUG_CREATED_FROM:
-					$t_note = lang_get( 'bug_created_from' );
-					$t_change = bug_format_id( $p_new_value );
+					$t_note = lang_get( 'bug_created_from' ) . ': ' . bug_format_id( $p_new_value );
 					break;
 				case TAG_ATTACHED:
 					$t_note = lang_get( 'tag_history_attached' ) . ': ' . $p_old_value;
```
