# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4307_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4307_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 208-248 of the vulnerable file.

		$t_button_title			= lang_get( 'product_version_group_bugs_button' );
		$t_form					= 'product_version';
		break;
	case 'UP_FIXED_IN_VERSION':
		$t_question_title		= lang_get( 'fixed_in_version_bugs_conf_msg' );
		$t_button_title			= lang_get( 'fixed_in_version_group_bugs_button' );
		$t_form					= 'fixed_in_version';
		break;
	case 'UP_TARGET_VERSION':
		$t_question_title		= lang_get( 'target_version_bugs_conf_msg' );
		$t_button_title			= lang_get( 'target_version_group_bugs_button' );
		$t_form					= 'target_version';
		break;
	case 'UP_DUE_DATE':
		$t_question_title		= lang_get( 'due_date_bugs_conf_msg' );
		$t_button_title			= lang_get( 'due_date_group_bugs_button' );
		$t_form					= 'due_date';
		break;
	case 'CUSTOM' :
		$t_custom_field_def = custom_field_get_definition( $t_custom_field_id );
		$t_question_title = sprintf( lang_get( 'actiongroup_menu_update_field' ), lang_get_defaulted( $t_custom_field_def['name'] ) );
		$t_button_title = $t_question_title;
		$t_form = 'custom_field_' . $t_custom_field_id;
		$t_event_params['custom_field_id'] = $t_custom_field_id;
		break;
	default:
		trigger_error( ERROR_GENERIC, ERROR );
}
$t_event_params['has_bugnote'] = $t_bugnote;

bug_group_action_print_top();
?>

<div class="col-md-12 col-xs-12">
<?php
if( $t_multiple_projects ) {
	echo '<div class="alert alert-warning"> <p class="bold">' . lang_get( 'multiple_projects' ) . '</p> </div>';
}
?>
<div id="action-group-div" class="form-container">
	<form method="post" action="bug_actiongroup.php">
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -225,7 +225,9 @@
 		break;
 	case 'CUSTOM' :
 		$t_custom_field_def = custom_field_get_definition( $t_custom_field_id );
-		$t_question_title = sprintf( lang_get( 'actiongroup_menu_update_field' ), lang_get_defaulted( $t_custom_field_def['name'] ) );
+		$t_question_title = sprintf( lang_get( 'actiongroup_menu_update_field' ),
+			string_attribute( lang_get_defaulted( $t_custom_field_def['name'] ) )
+		);
 		$t_button_title = $t_question_title;
 		$t_form = 'custom_field_' . $t_custom_field_id;
 		$t_event_params['custom_field_id'] = $t_custom_field_id;
```
