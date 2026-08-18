# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5747_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5747_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 163-203 of the vulnerable file.

	for ( $i = 0; $i < $t_sponsor_count; ++$i ) {
		$t_sponsor_row = $t_sponsors[$i];
		$t_bug = bug_get( $t_sponsor_row['bug'] );
		$t_sponsor = sponsorship_get( $t_sponsor_row['sponsor'] );

		# describe bug
		$t_status = string_attribute( get_enum_element( 'status', $t_bug->status, auth_get_current_user_id(), $t_bug->project_id ) );
		$t_resolution = string_attribute( get_enum_element( 'resolution', $t_bug->resolution, auth_get_current_user_id(), $t_bug->project_id ) );
		$t_version_id = version_get_id( $t_bug->fixed_in_version, $t_project );
		if ( ( false !== $t_version_id ) && ( VERSION_RELEASED == version_get_field( $t_version_id, 'released' ) ) ) {
			$t_released_label = '<a title="' . lang_get( 'released' ) . '">' . $t_bug->fixed_in_version . '</a>';
		} else {
			$t_released_label = $t_bug->fixed_in_version;
		}

		# choose color based on status
		$status_label = html_get_status_css_class( $t_bug->status, auth_get_current_user_id(), $t_bug->project_id );

		echo '<tr class="' . $status_label .  '">';
		echo '<td><a href="' . string_get_bug_view_url( $row['bug'] ) . '">' . bug_format_id( $row['bug'] ) . '</a></td>';
		echo '<td>' . project_get_field( $t_bug->project_id, 'name' ) . '&#160;</td>';
		echo '<td class="right">' . $t_released_label . '&#160;</td>';
		echo '<td><span class="issue-status" title="' . $t_resolution . '">' . $t_status . '</span></td>';
		echo '<td>';
		print_user( $t_bug->handler_id );
		echo '</td>';

		# summary
		echo '<td>' . string_display_line( $t_bug->summary );
		if ( VS_PRIVATE == $t_bug->view_state ) {
			printf( ' <img src="%s" alt="(%s)" title="%s" />', $t_icon_path . 'protected.gif', lang_get( 'private' ), lang_get( 'private' ) );
		}
		echo '</td>';

		# describe sponsorship amount
		echo '<td class="right">' . sponsorship_format_amount( $t_sponsor->amount ) . '</td>';
		echo '<td>' . get_enum_element( 'sponsorship', $t_sponsor->paid ) . '</td>';

		if ( SPONSORSHIP_PAID == $t_sponsor->paid ) {
			$t_total_paid += $t_sponsor->amount;
		} else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -180,7 +180,7 @@
 
 		echo '<tr class="' . $status_label .  '">';
 		echo '<td><a href="' . string_get_bug_view_url( $row['bug'] ) . '">' . bug_format_id( $row['bug'] ) . '</a></td>';
-		echo '<td>' . project_get_field( $t_bug->project_id, 'name' ) . '&#160;</td>';
+		echo '<td>' . string_display_line( project_get_field( $t_bug->project_id, 'name' ) ) . '&#160;</td>';
 		echo '<td class="right">' . $t_released_label . '&#160;</td>';
 		echo '<td><span class="issue-status" title="' . $t_resolution . '">' . $t_status . '</span></td>';
 		echo '<td>';
@@ -299,7 +299,7 @@
 
 		echo '<tr class="' . $status_label .  '">';
 		echo '<td><a href="' . string_get_bug_view_url( $row['bug'] ) . '">' . bug_format_id( $row['bug'] ) . '</a></td>';
-		echo '<td>' . project_get_field( $t_bug->project_id, 'name' ) . '&#160;</td>';
+		echo '<td>' . string_display_line( project_get_field( $t_bug->project_id, 'name' ) ) . '&#160;</td>';
 		echo '<td class="right">' . $t_released_label . '&#160;</td>';
 		echo '<td><a title="' . $t_resolution . '"><span class="underline">' . $t_status . '</span>&#160;</a></td>';
 
```
