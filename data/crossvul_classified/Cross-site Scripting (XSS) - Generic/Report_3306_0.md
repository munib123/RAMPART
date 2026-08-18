# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3306_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3306_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 29-69 of the vulnerable file.


if( !isset( $g_timeline_filter ) ) {
	$g_timeline_filter = null;
}
if( !isset( $g_timeline_user ) ) {
	$g_timeline_user = null;
}

$f_days = gpc_get_int( 'days', 0 );
$f_all = gpc_get_int( 'all', 0 );
$t_max_events = $f_all ? 0 : MAX_EVENTS + 1;

$t_end_time = time() - ( $f_days * SECONDS_PER_DAY );
$t_start_time = $t_end_time - ( 7 * SECONDS_PER_DAY );
$t_events = timeline_events( $t_start_time, $t_end_time, $t_max_events, $g_timeline_filter, $g_timeline_user );

$t_collapse_block = is_collapsed( 'timeline' );
$t_block_css = $t_collapse_block ? 'collapsed' : '';
$t_block_icon = $t_collapse_block ? 'fa-chevron-down' : 'fa-chevron-up';

$t_url_page = $_SERVER["PHP_SELF"];
$t_url_params = $_GET;
if( isset( $t_url_params['all'] ) ) {
	unset( $t_url_params['all'] );
}
?>

<div id="timeline" class="widget-box widget-color-blue2 <?php echo $t_block_css ?>">
	<div class="widget-header widget-header-small">
		<h4 class="widget-title lighter">
			<i class="ace-icon fa fa-clock-o"></i>
			<?php echo lang_get( 'timeline_title' ) ?>
		</h4>
		<div class="widget-toolbar">
			<a data-action="collapse" href="#">
				<i class="1 ace-icon fa <?php echo $t_block_icon ?> bigger-125"></i>
			</a>
		</div>
	</div>

	<div class="widget-body">
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -46,7 +46,7 @@
 $t_block_css = $t_collapse_block ? 'collapsed' : '';
 $t_block_icon = $t_collapse_block ? 'fa-chevron-down' : 'fa-chevron-up';
 
-$t_url_page = $_SERVER["PHP_SELF"];
+$t_url_page = string_sanitize_url( basename( $_SERVER['SCRIPT_NAME'] ) );
 $t_url_params = $_GET;
 if( isset( $t_url_params['all'] ) ) {
 	unset( $t_url_params['all'] );
```
